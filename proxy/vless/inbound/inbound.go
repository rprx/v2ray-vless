// +build !confonly

package inbound

//go:generate errorgen

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"regexp"
	"strconv"
	"sync"
	"time"

	"v2ray.com/core"
	"v2ray.com/core/common"
	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/errors"
	"v2ray.com/core/common/log"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/retry"
	"v2ray.com/core/common/session"
	"v2ray.com/core/common/signal"
	"v2ray.com/core/common/task"
	"v2ray.com/core/features/dns"
	feature_inbound "v2ray.com/core/features/inbound"
	"v2ray.com/core/features/policy"
	"v2ray.com/core/features/routing"
	"v2ray.com/core/proxy/vless"
	"v2ray.com/core/proxy/vless/encoding"
	"v2ray.com/core/transport/internet"
	"v2ray.com/core/transport/internet/tls"
)

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		var dc dns.Client
		if err := core.RequireFeatures(ctx, func(d dns.Client) error {
			dc = d
			return nil
		}); err != nil {
			return nil, err
		}
		return New(ctx, config.(*Config), dc)
	}))
}

// Handler is an inbound connection handler that handles messages in VLess protocol.
type Handler struct {
	inboundHandlerManager feature_inbound.Manager
	policyManager         policy.Manager
	validator             *vless.Validator
	dns                   dns.Client
	fallbacks             []*Fallback // or nil
	regexps               sync.Map
}

// New creates a new VLess inbound handler.
func New(ctx context.Context, config *Config, dc dns.Client) (*Handler, error) {

	v := core.MustFromContext(ctx)
	handler := &Handler{
		inboundHandlerManager: v.GetFeature(feature_inbound.ManagerType()).(feature_inbound.Manager),
		policyManager:         v.GetFeature(policy.ManagerType()).(policy.Manager),
		validator:             new(vless.Validator),
		dns:                   dc,
		fallbacks:             config.Fallbacks,
	}

	for _, user := range config.Clients {
		u, err := user.ToMemoryUser()
		if err != nil {
			return nil, newError("failed to get VLESS user").Base(err).AtError()
		}
		if err := handler.AddUser(ctx, u); err != nil {
			return nil, newError("failed to initiate user").Base(err).AtError()
		}
	}

	if handler.fallbacks != nil {
		for _, fb := range handler.fallbacks {
			if fb.Path != "" {
				if r, err := regexp.Compile(fb.Path); err != nil {
					return nil, newError("invalid path regexp").Base(err).AtError()
				} else {
					handler.regexps.Store(fb.Path, r)
				}
			}
		}
	}

	return handler, nil
}

// Close implements common.Closable.Close().
func (h *Handler) Close() error {
	return errors.Combine(common.Close(h.validator))
}

// AddUser implements proxy.UserManager.AddUser().
func (h *Handler) AddUser(ctx context.Context, u *protocol.MemoryUser) error {
	return h.validator.Add(u)
}

// RemoveUser implements proxy.UserManager.RemoveUser().
func (h *Handler) RemoveUser(ctx context.Context, e string) error {
	return h.validator.Del(e)
}

// Network implements proxy.Inbound.Network().
func (*Handler) Network() []net.Network {
	return []net.Network{net.Network_TCP}
}

// Process implements proxy.Inbound.Process().
func (h *Handler) Process(ctx context.Context, network net.Network, connection internet.Connection, dispatcher routing.Dispatcher) error {

	sessionPolicy := h.policyManager.ForLevel(0)
	if err := connection.SetReadDeadline(time.Now().Add(sessionPolicy.Timeouts.Handshake)); err != nil {
		return newError("unable to set read deadline").Base(err).AtWarning()
	}

	first := buf.New()
	first.ReadFrom(connection)

	reader := &buf.BufferedReader{
		Reader: buf.NewReader(connection),
		Buffer: buf.MultiBuffer{first},
	}

	var request *protocol.RequestHeader
	var requestAddons *encoding.Addons
	var err error
	var pre *buf.Buffer

	isfb := false
	firstBytes := []byte{}
	if h.fallbacks != nil {
		isfb = true
		firstBytes = first.Bytes()
	}

	sid := session.ExportIDToError(ctx)
	newError("firstLen = ", first.Len()).AtInfo().WriteToLog(sid)

	if isfb && first.Len() < 18 {
		err = newError("fallback directly")
	} else {
		request, requestAddons, err, pre = encoding.DecodeRequestHeader(reader, h.validator)
		if pre == nil {
			isfb = false
		}
	}

	if err != nil {

		if isfb {

			newError("fallback starts").Base(err).AtInfo().WriteToLog(sid)

			fallbacks := make(map[string]map[string]*Fallback)
			for _, fb := range h.fallbacks {
				fallbacks[fb.Alpn][fb.Path] = fb
			}

			alpn := ""
			path := ""

			if len(fallbacks) > 1 || fallbacks[""] == nil {
				iConn := connection
				if statConn, ok := iConn.(*internet.StatCouterConnection); ok {
					iConn = statConn.Connection
				}
				if tlsConn, ok := iConn.(*tls.Conn); ok {
					alpn = tlsConn.ConnectionState().NegotiatedProtocol
					newError("realAlpn = " + alpn).AtInfo().WriteToLog(sid)
					if fallbacks[alpn] == nil {
						alpn = ""
					}
				}
			}
			newError("fallback as alpn \"" + alpn + "\"").AtInfo().WriteToLog(sid)
			if fallbacks[alpn] == nil {
				return newError("failed to find the default config").AtWarning()
			}

			if len(fallbacks[alpn]) > 1 || fallbacks[alpn][""] == nil {
				if lines := bytes.Split(firstBytes, []byte{'\r', '\n'}); len(lines) > 1 {
					if s := bytes.Split(lines[0], []byte{' '}); len(s) == 3 {
						if len(s[0]) < 8 && len(s[1]) > 0 && len(s[2]) == 8 {
							newError("realPath = " + string(s[1])).AtInfo().WriteToLog(sid)
							for _, fb := range fallbacks[alpn] {
								if fb.Path != "" {
									if r, _ := h.regexps.Load(fb.Path); r != nil {
										if r.(*regexp.Regexp).Match(s[1]) {
											path = fb.Path
											break
										}
									}
								}
							}
						}
					}
				}
			}
			newError("fallback as path \"" + path + "\"").AtInfo().WriteToLog(sid)
			fb := fallbacks[alpn][path]
			if fb == nil {
				return newError("failed to find the default config").AtWarning()
			}

			var conn net.Conn
			if err := retry.ExponentialBackoff(5, 100).On(func() error {
				var dialer net.Dialer
				conn, err = dialer.DialContext(ctx, fb.Type, fb.Dest)
				if err != nil {
					return err
				}
				return nil
			}); err != nil {
				return newError("failed to fallback connection").Base(err).AtWarning()
			}
			defer conn.Close() // nolint: errcheck

			ctx, cancel := context.WithCancel(ctx)
			timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

			writer := buf.NewWriter(connection)

			serverReader := buf.NewReader(conn)
			serverWriter := buf.NewWriter(conn)

			postRequest := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
				if fb.Xver != 0 {
					remoteAddr, remotePort, err := net.SplitHostPort(connection.RemoteAddr().String())
					if err != nil {
						return err
					}
					localAddr, localPort, err := net.SplitHostPort(connection.LocalAddr().String())
					if err != nil {
						return err
					}
					ipv4 := true
					for i := 0; i < len(remoteAddr); i++ {
						if remoteAddr[i] == ':' {
							ipv4 = false
							break
						}
					}
					pro := buf.New()
					switch fb.Xver {
					case 1:
						if ipv4 {
							pro.Write([]byte("PROXY TCP4 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						} else {
							pro.Write([]byte("PROXY TCP6 " + remoteAddr + " " + localAddr + " " + remotePort + " " + localPort + "\r\n"))
						}
					case 2:
						pro.Write([]byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21")) // signature + v2 + PROXY
						if ipv4 {
							pro.Write([]byte("\x11\x00\x0C")) // AF_INET + STREAM + 12 bytes
							pro.Write(net.ParseIP(remoteAddr).To4())
							pro.Write(net.ParseIP(localAddr).To4())
						} else {
							pro.Write([]byte("\x21\x00\x24")) // AF_INET6 + STREAM + 36 bytes
							pro.Write(net.ParseIP(remoteAddr).To16())
							pro.Write(net.ParseIP(localAddr).To16())
						}
						p1, _ := strconv.ParseInt(remotePort, 10, 64)
						b1, _ := hex.DecodeString(strconv.FormatInt(p1, 16))
						p2, _ := strconv.ParseInt(localPort, 10, 64)
						b2, _ := hex.DecodeString(strconv.FormatInt(p2, 16))
						if len(b1) == 1 {
							pro.WriteByte(0)
						}
						pro.Write(b1)
						if len(b2) == 1 {
							pro.WriteByte(0)
						}
						pro.Write(b2)
					}
					if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{pro}); err != nil {
						return newError("failed to set PROXY protocol v", fb.Xver).Base(err).AtWarning()
					}
				}
				if pre != nil && pre.Len() > 0 {
					if err := serverWriter.WriteMultiBuffer(buf.MultiBuffer{pre}); err != nil {
						return newError("failed to fallback request pre").Base(err).AtWarning()
					}
				}
				if err := buf.Copy(reader, serverWriter, buf.UpdateActivity(timer)); err != nil {
					return err // ...
				}
				return nil
			}

			getResponse := func() error {
				defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
				if err := buf.Copy(serverReader, writer, buf.UpdateActivity(timer)); err != nil {
					return err // ...
				}
				return nil
			}

			if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), task.OnSuccess(getResponse, task.Close(writer))); err != nil {
				common.Interrupt(serverReader)
				common.Interrupt(serverWriter)
				return newError("fallback ends").Base(err).AtInfo()
			}
			return nil
		}

		if errors.Cause(err) != io.EOF {
			log.Record(&log.AccessMessage{
				From:   connection.RemoteAddr(),
				To:     "",
				Status: log.AccessRejected,
				Reason: err,
			})
			err = newError("invalid request from ", connection.RemoteAddr()).Base(err).AtWarning()
		}
		return err
	}

	if request.Command != protocol.RequestCommandMux {
		ctx = log.ContextWithAccessMessage(ctx, &log.AccessMessage{
			From:   connection.RemoteAddr(),
			To:     request.Destination(),
			Status: log.AccessAccepted,
			Reason: "",
			Email:  request.User.Email,
		})
	}

	newError("received request for ", request.Destination()).AtInfo().WriteToLog(sid)

	if err := connection.SetReadDeadline(time.Time{}); err != nil {
		newError("unable to set back read deadline").Base(err).AtWarning().WriteToLog(sid)
	}

	inbound := session.InboundFromContext(ctx)
	if inbound == nil {
		panic("no inbound metadata")
	}
	inbound.User = request.User

	sessionPolicy = h.policyManager.ForLevel(request.User.Level)

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	ctx = policy.ContextWithBufferPolicy(ctx, sessionPolicy.Buffer)
	link, err := dispatcher.Dispatch(ctx, request.Destination())
	if err != nil {
		return newError("failed to dispatch request to ", request.Destination()).Base(err).AtWarning()
	}

	serverReader := link.Reader
	serverWriter := link.Writer

	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)

		// default: clientReader := reader
		clientReader := encoding.DecodeBodyAddons(reader, request, requestAddons)

		// from clientReader.ReadMultiBuffer to serverWriter.WriteMultiBufer
		if err := buf.Copy(clientReader, serverWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transfer request payload").Base(err).AtInfo()
		}

		return nil
	}

	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)

		responseAddons := &encoding.Addons{
			Scheduler: requestAddons.Scheduler,
		}

		bufferWriter := buf.NewBufferedWriter(buf.NewWriter(connection))
		if err := encoding.EncodeResponseHeader(bufferWriter, request, responseAddons); err != nil {
			return newError("failed to encode response header").Base(err).AtWarning()
		}

		// default: clientWriter := bufferWriter
		clientWriter := encoding.EncodeBodyAddons(bufferWriter, request, responseAddons)
		{
			multiBuffer, err := serverReader.ReadMultiBuffer()
			if err != nil {
				return err // ...
			}
			if err := clientWriter.WriteMultiBuffer(multiBuffer); err != nil {
				return err // ...
			}
		}

		// Flush; bufferWriter.WriteMultiBufer now is bufferWriter.writer.WriteMultiBuffer
		if err := bufferWriter.SetBuffered(false); err != nil {
			return newError("failed to write A response payload").Base(err).AtWarning()
		}

		// from serverReader.ReadMultiBuffer to clientWriter.WriteMultiBufer
		if err := buf.Copy(serverReader, clientWriter, buf.UpdateActivity(timer)); err != nil {
			return newError("failed to transfer response payload").Base(err).AtInfo()
		}

		// Indicates the end of response payload.
		switch responseAddons.Scheduler {
		default:

		}

		return nil
	}

	if err := task.Run(ctx, task.OnSuccess(postRequest, task.Close(serverWriter)), getResponse); err != nil {
		common.Interrupt(serverReader)
		common.Interrupt(serverWriter)
		return newError("connection ends").Base(err).AtInfo()
	}

	return nil
}
