'use strict';

/* This public walkthrough is a pure, in-memory simulation. It never calls the
   local broker, creates credentials, persists content, or sends a message. */
const SilkWalkthrough = (() => {
  const durations = Object.freeze([60, 300, 900]);
  const initial = () => ({ phase: 'ready', duration: 300, expiresAt: null, remaining: 1, receipt: false, events: [] });
  const expired = (state, now) => state.expiresAt !== null && now >= state.expiresAt && !['revoked', 'expired', 'declined'].includes(state.phase);
  function transition(state, action, now = Date.now(), value) {
    if (action === 'reset') return initial();
    if (expired(state, now)) return { ...state, phase: 'expired', events: [...state.events, 'Example permission expired. Further activity is blocked.'] };
    if (action === 'duration' && state.phase === 'ready' && durations.includes(value)) return { ...state, duration: value };
    if (action === 'invite' && state.phase === 'ready') return { ...state, phase: 'invited', events: ['Example invitation created. No access granted.'] };
    if (action === 'decline' && state.phase === 'invited') return { ...state, phase: 'declined', events: [...state.events, 'Receiving owner declined the example invitation.'] };
    if (action === 'consent' && state.phase === 'invited') return { ...state, phase: 'consented', expiresAt: now + state.duration * 1000, events: [...state.events, 'Receiving owner gave simulated consent for one proposal.'] };
    if (action === 'propose' && state.phase === 'consented' && state.remaining > 0) return { ...state, phase: 'proposed', remaining: 0, events: [...state.events, 'Agent A proposed the sample time. Owner review required.'] };
    if (action === 'approve' && state.phase === 'proposed') return { ...state, phase: 'approved', receipt: true, events: [...state.events, 'Owner approved the example result. No meeting was booked.'] };
    if (action === 'revoke' && ['consented', 'proposed', 'approved'].includes(state.phase)) return { ...state, phase: 'revoked', events: [...state.events, state.receipt ? 'Example access revoked. The existing receipt is retained.' : 'Example access revoked. Unapproved work is cancelled.'] };
    return state;
  }
  function validStatus(data) {
    if (!data || data.product !== 'Silk' || data.stage !== 'development_preview' || data.live_messaging !== false) return false;
    if (data.owner_authentication?.state !== 'not_configured' || data.durable_storage?.state !== 'not_configured') return false;
    if (!Array.isArray(data.connections)) return false;
    return ['grok', 'dot'].every(id => data.connections.some(item => item && item.id === id && item.connected === false && item.inbound === 'unverified' && item.outbound === 'unverified'));
  }
  return Object.freeze({ initial, transition, validStatus, durations });
})();

if (typeof module !== 'undefined' && module.exports) module.exports = SilkWalkthrough;

if (typeof document !== 'undefined') {
  (() => {
    const byId = id => document.getElementById(id);
    const elements = {
      duration: byId('duration'), advance: byId('advance'), decline: byId('decline'), revoke: byId('revoke'), reset: byId('reset'),
      kicker: byId('stage-kicker'), title: byId('stage-title'), description: byId('stage-description'), note: byId('action-note'),
      sample: byId('sample-time'), grantStatus: byId('grant-status'), grantDetail: byId('grant-detail'), grantIndicator: byId('grant-indicator'),
      activity: byId('activity-list'), receipt: byId('receipt'), announcer: byId('announcer'), statusSource: byId('status-source')
    };
    const steps = [...document.querySelectorAll('[data-step]')];
    const copy = {
      ready: { step: 0, kicker: 'STEP 1 OF 4 · SENDER’S OWNER', title: 'Open the conversation.', description: 'Invite Agent B to suggest one meeting time. An invitation alone gives no access.', button: 'Create example invite', action: 'invite', note: 'You’re trying an example, not signing in or granting real access.' },
      invited: { step: 1, kicker: 'STEP 2 OF 4 · RECEIVING OWNER', title: 'Make the permission yours.', description: 'Review the purpose, limit, and lifetime. Only consent opens this example connection.', button: 'Give demo consent', action: 'consent', note: 'Simulated consent applies only to this fictional walkthrough.' },
      consented: { step: 2, kicker: 'STEP 3 OF 4 · SENDER’S AGENT', title: 'One purpose. One proposal.', description: 'The example permission is open. Agent A can propose one sample meeting time within the agreed scope.', button: 'Propose sample time', action: 'propose', note: 'This uses invented data. No calendars or providers are connected.' },
      proposed: { step: 3, kicker: 'STEP 4 OF 4 · RECEIVING OWNER', title: 'The last word is yours.', description: 'Review the proposed time below. Approving creates an example receipt, with no external action.', button: 'Approve sample result', action: 'approve', note: 'Revoke access instead if you want to cancel this unapproved proposal.' },
      approved: { step: 4, kicker: 'WALKTHROUGH COMPLETE', title: 'A clear decision. A little receipt.', description: 'You approved the example proposal. The receipt records that choice. No message was sent and no meeting was booked.', button: 'Example approved', action: null, note: 'Try revoking access: the completed receipt stays until you reset.' },
      declined: { step: 1, kicker: 'INVITATION DECLINED', title: 'No is a complete answer.', description: 'The example invitation was declined. No access was granted and no proposal can be sent.', button: 'Invitation declined', action: null, note: 'Reset the example whenever you want to try again.' },
      revoked: { step: -1, kicker: 'ACCESS REVOKED', title: 'You can close the line.', description: 'The example permission is revoked. Further proposals and approvals are blocked.', button: 'Access revoked', action: null, note: 'Any completed example receipt remains visible until you reset.' },
      expired: { step: -1, kicker: 'PERMISSION EXPIRED', title: 'A boundary that holds.', description: 'The example permission reached its time limit. Further proposals and approvals are blocked.', button: 'Permission expired', action: null, note: 'Any completed example receipt remains visible. Reset to start again.' }
    };
    let state = SilkWalkthrough.initial();
    let clock = null;
    function countdown(now) {
      const seconds = Math.max(0, Math.ceil((state.expiresAt - now) / 1000));
      const minutes = Math.floor(seconds / 60);
      return `${minutes}:${String(seconds % 60).padStart(2, '0')}`;
    }
    function updateGrant(now) {
      const active = ['consented', 'proposed', 'approved'].includes(state.phase);
      elements.grantIndicator.dataset.state = active ? 'active' : ['revoked', 'expired', 'declined'].includes(state.phase) ? 'closed' : 'idle';
      if (active) {
        elements.grantStatus.textContent = 'Example permission active';
        elements.grantDetail.textContent = `${state.remaining} proposal${state.remaining === 1 ? '' : 's'} remaining · Expires in ${countdown(now)}`;
      } else {
        const labels = {
          ready: ['No permission granted', 'Waiting for an invitation'],
          invited: ['Consent required', 'Invitation pending · No access yet'],
          declined: ['Invitation declined', 'No permission was granted'],
          revoked: ['Example access revoked', 'Further activity is blocked'],
          expired: ['Example permission expired', 'The time limit has been reached']
        };
        [elements.grantStatus.textContent, elements.grantDetail.textContent] = labels[state.phase];
      }
    }
    function syncClock() {
      const active = ['consented', 'proposed', 'approved'].includes(state.phase);
      if (active && clock === null) clock = setInterval(() => {
        const now = Date.now();
        const next = SilkWalkthrough.transition(state, 'tick', now);
        if (next !== state) { state = next; render(true); } else updateGrant(now);
      }, 1000);
      if (!active && clock !== null) { clearInterval(clock); clock = null; }
    }
    function render(announce = false) {
      const current = copy[state.phase];
      elements.kicker.textContent = current.kicker;
      elements.title.textContent = current.title;
      elements.description.textContent = current.description;
      elements.note.textContent = current.note;
      elements.advance.textContent = current.button;
      elements.advance.disabled = current.action === null;
      elements.decline.hidden = state.phase !== 'invited';
      elements.revoke.disabled = !['consented', 'proposed', 'approved'].includes(state.phase);
      elements.reset.disabled = state.phase === 'ready' && state.duration === 300;
      elements.duration.disabled = state.phase !== 'ready';
      elements.duration.value = String(state.duration);
      elements.sample.hidden = !['proposed', 'approved'].includes(state.phase) && !state.receipt;
      elements.receipt.hidden = !state.receipt;
      steps.forEach((step, index) => {
        if (index === current.step) step.setAttribute('aria-current', 'step'); else step.removeAttribute('aria-current');
        step.dataset.complete = String(current.step > index);
      });
      elements.activity.replaceChildren();
      const events = state.events.length ? state.events : ['Your example activity will appear here.'];
      events.forEach(message => {
        const item = document.createElement('li');
        if (!state.events.length) item.className = 'empty-activity';
        item.textContent = message;
        elements.activity.append(item);
      });
      updateGrant(Date.now());
      if (announce) {
        elements.announcer.textContent = `${current.title} ${current.description}`;
        const focused = document.activeElement;
        if ([elements.advance, elements.decline, elements.revoke].includes(focused) && (focused.disabled || focused.hidden)) elements.reset.focus();
      }
      syncClock();
    }
    function act(action, value) {
      state = SilkWalkthrough.transition(state, action, Date.now(), value);
      render(true);
    }
    elements.advance.addEventListener('click', event => {
      // A double-click on one step must not accidentally consent to the next.
      if (event.detail > 1) return;
      const action = copy[state.phase].action;
      if (action) act(action);
    });
    elements.decline.addEventListener('click', () => act('decline'));
    elements.revoke.addEventListener('click', () => act('revoke'));
    elements.reset.addEventListener('click', () => { act('reset'); elements.advance.focus(); });
    elements.duration.addEventListener('change', event => act('duration', Number(event.target.value)));
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        const next = SilkWalkthrough.transition(state, 'tick', Date.now());
        const changed = next !== state;
        state = next;
        render(changed);
      }
    });
    render();

    // Only one same-origin, read-only request. No cookies, redirects, or content.
    async function checkStatus() {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        const response = await fetch('/api/status', { method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error', signal: controller.signal, headers: { Accept: 'application/json' } });
        if (!response.ok) throw new Error('Status unavailable');
        const status = await response.json();
        if (!SilkWalkthrough.validStatus(status)) throw new Error('Status unverified');
        elements.statusSource.textContent = 'Development status checked. Live messaging is not enabled.';
      } catch {
        elements.statusSource.textContent = 'Status service unavailable. Grok → dot remains not connected.';
      } finally {
        clearTimeout(timeout);
      }
    }
    void checkStatus();
  })();
}
