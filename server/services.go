// SPDX-License-Identifier: BSD-3-Clause

package server

import (
	"context"
	"net/http"

	"connectrpc.com/connect/v2"

	"github.com/go-wasmcontainers/relay/firewall"
	v1 "github.com/go-wasmcontainers/relay/gen/relayv1"
	"github.com/go-wasmcontainers/relay/gen/relayv1/relayv1connect"
	"github.com/go-wasmcontainers/relay/relay"
)

// services implements every control-API service. Authorization is decided
// here, from the principal the HTTP layer established — never from a field
// of the request.
type services struct{ s *Server }

var (
	_ relayv1connect.ClassServiceHandler         = (*services)(nil)
	_ relayv1connect.JoinServiceHandler          = (*services)(nil)
	_ relayv1connect.SecurityGroupServiceHandler = (*services)(nil)
	_ relayv1connect.PortServiceHandler          = (*services)(nil)
	_ relayv1connect.FlowLogServiceHandler       = (*services)(nil)
)

var errUnauth = connect.NewError(connect.CodeUnauthenticated, "unauthenticated")
var errDenied = connect.NewError(connect.CodePermissionDenied, "the teacher's role is needed")

func cerr(err error) error {
	if err == nil {
		return nil
	}
	code := connect.CodeInternal
	switch relay.ErrKind(err) {
	case relay.KindInvalid:
		code = connect.CodeInvalidArgument
	case relay.KindNotFound:
		code = connect.CodeNotFound
	case relay.KindExists:
		code = connect.CodeAlreadyExists
	case relay.KindDenied:
		code = connect.CodePermissionDenied
	case relay.KindLimit:
		code = connect.CodeResourceExhausted
	case relay.KindUnauthenticated:
		code = connect.CodeUnauthenticated
	default:
		return connect.NewError(code, "internal error")
	}
	return connect.NewError(code, err.Error())
}

func admin(ctx context.Context) error {
	if !principal(ctx).Admin {
		return errDenied
	}
	return nil
}

// student returns the calling session, for a call a student may make about
// its own class only.
func student(ctx context.Context, classID string) (string, error) {
	p := principal(ctx)
	if p.Admin {
		return "", nil
	}
	if p.Session == nil {
		return "", errUnauth
	}
	if p.Session.Class != classID {
		return "", errDenied
	}
	return p.Session.Session, nil
}

// ------------------------------------------------------------------ classes

func (sv *services) CreateClass(ctx context.Context, r *v1.CreateClassRequest) (*v1.Class, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	if r.RequireIdentity && sv.s.cfg.OIDC == nil {
		return nil, connect.NewError(connect.CodeFailedPrecondition, "require_identity needs an OpenID Connect issuer (--oidc-issuer)")
	}
	c, err := sv.s.cfg.Relay.CreateClass(relay.ClassSpec{Name: r.Name, CIDR: r.Cidr, SessionBits: int(r.SessionBits),
		DNSDomain: r.DnsDomain, Template: r.Template, Allowed: r.Allowed, RequireID: r.RequireIdentity})
	return c, cerr(err)
}

func (sv *services) GetClass(ctx context.Context, r *v1.GetClassRequest) (*v1.Class, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	c, err := sv.s.cfg.Relay.GetClass(r.Id, true)
	return c, cerr(err)
}

func (sv *services) DeleteClass(ctx context.Context, r *v1.DeleteClassRequest) (*v1.DeleteClassResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	return &v1.DeleteClassResponse{}, cerr(sv.s.cfg.Relay.DeleteClass(r.Id))
}

func (sv *services) ListClasses(ctx context.Context, _ *v1.ListClassesRequest) (*v1.ListClassesResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	return &v1.ListClassesResponse{Classes: sv.s.cfg.Relay.ListClasses()}, nil
}

func (sv *services) RotateJoinCode(ctx context.Context, r *v1.RotateJoinCodeRequest) (*v1.Class, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	c, err := sv.s.cfg.Relay.RotateJoinCode(r.ClassId)
	return c, cerr(err)
}

func (sv *services) ListSessions(ctx context.Context, r *v1.ListSessionsRequest) (*v1.ListSessionsResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	ss, err := sv.s.cfg.Relay.ListSessions(r.ClassId)
	return &v1.ListSessionsResponse{Sessions: ss}, cerr(err)
}

func (sv *services) KickSession(ctx context.Context, r *v1.KickSessionRequest) (*v1.KickSessionResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	return &v1.KickSessionResponse{}, cerr(sv.s.cfg.Relay.KickSession(r.ClassId, r.Session))
}

// --------------------------------------------------------------------- join

func requestOf(ctx context.Context) *http.Request {
	r, _ := ctx.Value(requestKey{}).(*http.Request)
	return r
}

type requestKey struct{}

func (sv *services) oidcIdentity(ctx context.Context) *relay.Identity {
	p := principal(ctx)
	if p.Identity != nil {
		return p.Identity
	}
	if r := requestOf(ctx); r != nil {
		return sv.s.identity(ctx, bearer(r))
	}
	return nil
}

func joined(j *relay.Joined) *v1.JoinResponse {
	return &v1.JoinResponse{SessionToken: j.Token, Session: j.Session, Class: j.Class}
}

func (sv *services) Join(ctx context.Context, r *v1.JoinRequest) (*v1.JoinResponse, error) {
	if req := requestOf(ctx); req != nil && !sv.s.ipl.allow(clientIP(req)) {
		return nil, connect.NewError(connect.CodeResourceExhausted, "too many attempts; wait a minute")
	}
	j, err := sv.s.cfg.Relay.Join(r.JoinCode, r.DisplayName, sv.oidcIdentity(ctx))
	if err != nil {
		return nil, cerr(err)
	}
	return joined(j), nil
}

func (sv *services) RefreshSession(ctx context.Context, r *v1.RefreshSessionRequest) (*v1.RefreshSessionResponse, error) {
	j, err := sv.s.cfg.Relay.Refresh(r.SessionToken, sv.oidcIdentity(ctx))
	if err != nil {
		return nil, cerr(err)
	}
	return &v1.RefreshSessionResponse{SessionToken: j.Token, ExpiresUnix: j.Expires.Unix()}, nil
}

func (sv *services) TeacherSession(ctx context.Context, r *v1.TeacherSessionRequest) (*v1.JoinResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	j, err := sv.s.cfg.Relay.TeacherSession(r.ClassId)
	if err != nil {
		return nil, cerr(err)
	}
	return joined(j), nil
}

// ---------------------------------------------------------- security groups

func (sv *services) ListSecurityGroups(ctx context.Context, r *v1.ListSecurityGroupsRequest) (*v1.ListSecurityGroupsResponse, error) {
	if _, err := student(ctx, r.ClassId); err != nil {
		return nil, err
	}
	gs, err := sv.s.cfg.Relay.ListSecurityGroups(r.ClassId)
	return &v1.ListSecurityGroupsResponse{SecurityGroups: gs}, cerr(err)
}

func (sv *services) CreateSecurityGroup(ctx context.Context, r *v1.CreateSecurityGroupRequest) (*v1.SecurityGroup, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	g, err := sv.s.cfg.Relay.CreateSecurityGroup(r.ClassId, r.Name, r.Description, r.Stateless)
	return g, cerr(err)
}

func (sv *services) DeleteSecurityGroup(ctx context.Context, r *v1.DeleteSecurityGroupRequest) (*v1.DeleteSecurityGroupResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	return &v1.DeleteSecurityGroupResponse{}, cerr(sv.s.cfg.Relay.DeleteSecurityGroup(r.ClassId, r.Group))
}

func (sv *services) CreateRule(ctx context.Context, r *v1.CreateRuleRequest) (*v1.SecurityGroupRule, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	rule, err := sv.s.cfg.Relay.CreateRule(r.ClassId, r.Group, r.Rule)
	return rule, cerr(err)
}

func (sv *services) DeleteRule(ctx context.Context, r *v1.DeleteRuleRequest) (*v1.DeleteRuleResponse, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	return &v1.DeleteRuleResponse{}, cerr(sv.s.cfg.Relay.DeleteRule(r.ClassId, r.RuleId))
}

func (sv *services) ExplainFlow(ctx context.Context, r *v1.ExplainFlowRequest) (*v1.FlowEvent, error) {
	sess, err := student(ctx, r.ClassId)
	if err != nil {
		return nil, err
	}
	if r.DstPort > 65535 {
		return nil, connect.NewError(connect.CodeInvalidArgument, "port above 65535")
	}
	ev, err := sv.s.cfg.Relay.ExplainFlow(r.ClassId, r.Src, r.Dst, firewall.Protocol(r.Protocol), uint16(r.DstPort))
	if err != nil {
		return nil, cerr(err)
	}
	if sess != "" && ev.SrcSession != sess && ev.DstSession != sess {
		return nil, errDenied
	}
	return ev, nil
}

// -------------------------------------------------------------------- ports

func (sv *services) ListPorts(ctx context.Context, r *v1.ListPortsRequest) (*v1.ListPortsResponse, error) {
	sess, err := student(ctx, r.ClassId)
	if err != nil {
		return nil, err
	}
	who := r.Session
	if sess != "" {
		who = sess // a student sees only their own ports
	}
	ps, err := sv.s.cfg.Relay.ListPorts(r.ClassId, who)
	return &v1.ListPortsResponse{Ports: ps}, cerr(err)
}

func (sv *services) UpdatePort(ctx context.Context, r *v1.UpdatePortRequest) (*v1.Port, error) {
	if err := admin(ctx); err != nil {
		return nil, err
	}
	p, err := sv.s.cfg.Relay.UpdatePort(r.ClassId, r.Port, r.SecurityGroups, r.SetSecurityGroups, r.PortSecurityEnabled)
	return p, cerr(err)
}

// ----------------------------------------------------------------- flow log

func (sv *services) WatchFlows(ctx context.Context, r *v1.WatchFlowsRequest, out relayv1connect.FlowLogServiceWatchFlowsServerStream) error {
	sess, err := student(ctx, r.ClassId)
	if err != nil {
		return err
	}
	who := ""
	if sess != "" {
		who = sess
	} else if r.Session != "" {
		if who, err = sv.s.cfg.Relay.SessionOf(r.ClassId, r.Session); err != nil {
			return cerr(err)
		}
	}
	// Headers now: a client waits for them before its first Receive.
	if err := out.SendHeaders(); err != nil {
		return err
	}
	err = sv.s.cfg.Relay.WatchFlows(ctx, r.ClassId, who, r.DenyOnly, int(r.Backlog), func(e *v1.FlowEvent) error { return out.Send(e) })
	if err == context.Canceled {
		return nil
	}
	return cerr(err)
}
