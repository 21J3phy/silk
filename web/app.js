'use strict';

(() => {
  const $ = (id) => document.getElementById(id);
  let session = null;
  let state = null;
  let ownerId = null;
  let epoch = 0;
  let busy = false;
  let online = false;
  let stateController = null;
  let stateSequence = 0;
  let nextAction = null;
  let invitationTarget = null;
  let composeGrantId = null;
  let pendingMessageAttempt = null;
  let optionsOwner = null;
  const renderKeys = new Map();

  const statusNames = {
    pending: 'Pending consent', accepted: 'Accepted', declined: 'Declined',
    expired: 'Expired', active: 'Active grant', revoked: 'Revoked',
    queued: 'In the queue', awaiting_approval: 'Needs approval', approved: 'Approved',
    rejected: 'Rejected', cancelled: 'Cancelled'
  };
  const auditNames = {
    'invitation.created': 'Invitation sent', 'invitation.accepted': 'Recipient consent recorded',
    'invitation.declined': 'Invitation declined', 'invitation.expired': 'Invitation expired',
    'grant.created': 'Scoped grant created', 'grant.revoked': 'Grant revoked',
    'grant.expired': 'Grant expired', 'message.queued': 'Signed request queued',
    'message.received': 'Request received', 'message.delivered': 'Delivered to local mock', 'message.dispatched': 'Mock agent compared options',
    'message.awaiting_approval': 'Proposal ready for owner review',
    'message.approved': 'Owner approved proposal', 'message.declined': 'Owner declined proposal',
    'message.cancelled': 'Pending request cancelled', 'message.expired': 'Request expired',
    'message.rejected': 'Request rejected', 'receipt.created': 'Shared receipt created'
  };

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function text(id, value) { $(id).textContent = value; }
  function show(node, visible) { node.classList.toggle('hidden', !visible); }
  function announce(message) { text('live-status', message); }
  function nameOfAgent(id) { return state?.agents.find((a) => a.id === id)?.name || id; }
  function agentById(id) { return state?.agents.find((a) => a.id === id); }
  function ownerOfAgent(id) { return agentById(id)?.owner_id; }
  function ownerName(id) { return state?.owners.find((o) => o.id === id)?.name || id; }
  function firstName(id) { return ownerName(id).split(' ')[0]; }
  function myAgent() { return state?.agents.find((a) => a.owner_id === ownerId); }
  function otherAgent() { return state?.agents.find((a) => a.owner_id !== ownerId); }
  function route(from, to) { return `${nameOfAgent(from)} → ${nameOfAgent(to)}`; }
  function newest(items) { return [...items].sort((a, b) => b.created_at - a.created_at || String(b.id).localeCompare(String(a.id))); }
  function stamp(seconds) {
    const date = new Date(Number(seconds) * 1000);
    if (!Number.isFinite(date.getTime())) return 'Unknown time';
    return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' }).format(date) + ' UTC';
  }
  function clockTime(seconds) {
    const date = new Date(Number(seconds) * 1000);
    if (!Number.isFinite(date.getTime())) return '—';
    return new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' }).format(date);
  }
  function optionText(option) {
    if (!option) return 'No selected time';
    const start = new Date(option.start);
    if (!Number.isFinite(start.getTime())) return 'Invalid sample time';
    const end = new Date(start.getTime() + Number(option.duration_minutes) * 60000);
    const date = new Intl.DateTimeFormat('en-US', { weekday: 'short', month: 'short', day: 'numeric', timeZone: 'UTC' }).format(start);
    const time = new Intl.DateTimeFormat('en-US', { hour: '2-digit', minute: '2-digit', hourCycle: 'h23', timeZone: 'UTC' });
    return `${date} · ${time.format(start)}–${time.format(end)} UTC`;
  }
  function sameOption(a, b) { return !!a && !!b && a.start === b.start && a.duration_minutes === b.duration_minutes; }
  function badge(status) { return el('span', `status-badge ${status}`, statusNames[status] || status.replaceAll('_', ' ')); }
  function apiPath(kind, id, action) { return `/api/${kind}/${encodeURIComponent(id)}/${action}`; }

  function actionButton(label, handler, { variant = 'quiet', action = '', entityId = '', small = true } = {}) {
    const button = el('button', `button button-${variant}${small ? ' button-small' : ''}`, label);
    button.type = 'button';
    button.dataset.mutation = 'true';
    if (action) button.dataset.action = action;
    if (entityId) button.dataset.entityId = entityId;
    button.addEventListener('click', handler);
    return button;
  }

  function clearError() {
    show($('error-notice'), false);
    text('error-message', '');
  }
  function showError(message, reconnect = false, title = 'Something needs attention') {
    text('error-title', title);
    text('error-message', message);
    show($('retry-connection'), reconnect);
    show($('error-notice'), true);
  }
  function setOnline(value) {
    online = value;
    const indicator = $('connection-status');
    const connectionLabel = value ? 'online' : session ? 'offline' : 'connecting';
    if (indicator.dataset.state === connectionLabel) return;
    indicator.dataset.state = connectionLabel;
    indicator.classList.toggle('online', value);
    indicator.classList.toggle('offline', !value && !!session);
    indicator.replaceChildren(el('span'), document.createTextNode(value ? 'Live · refreshes every 2s' : session ? 'Connection interrupted' : 'Connecting…'));
  }
  function syncControls() {
    const locked = busy || !state || !session || !online;
    document.querySelectorAll('[data-mutation]').forEach((button) => { button.disabled = locked || button.dataset.unavailable === 'true'; });
    $('owner-select').disabled = busy || !session;
    $('next-action').disabled = locked;
    $('retry-connection').disabled = busy;
    ['invitation-purpose', 'meeting-title'].forEach((id) => { $(id).disabled = locked; });
    $('meeting-options').querySelectorAll('input').forEach((input) => { input.disabled = locked; });
    $('close-invitation').disabled = busy;
    $('close-composer').disabled = busy;
    document.querySelectorAll('[data-owner-switch]').forEach((button) => { button.disabled = locked; });
    $('workspace').setAttribute('aria-busy', String(busy));
  }

  async function requestJSON(path, payload, signal) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort();
    else signal?.addEventListener('abort', abort, { once: true });
    const timeout = window.setTimeout(() => controller.abort(), 12000);
    const headers = { Accept: 'application/json' };
    const options = { method: payload === undefined ? 'GET' : 'POST', headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: controller.signal };
    if (payload !== undefined) {
      headers['Content-Type'] = 'application/json';
      headers['X-CSRF-Token'] = session?.csrf_token || '';
      options.body = JSON.stringify(payload);
    }
    try {
      const response = await fetch(path, options);
      let body;
      try { body = await response.json(); }
      catch (_) { const error = new Error('The local server returned an unreadable response.'); error.uncertain = true; throw error; }
      if (!response.ok) {
        const error = new Error(body?.error?.message || `The request failed (${response.status}).`);
        error.code = body?.error?.code;
        error.status = response.status;
        error.uncertain = response.status >= 500;
        throw error;
      }
      return body;
    } catch (error) {
      if (error.name === 'AbortError' && signal?.aborted) throw error;
      if (!error.status && !error.code) {
        error.uncertain = true;
        if (error.name === 'AbortError') error.message = 'The local server took too long to respond.';
        else if (error instanceof TypeError) error.message = 'Couldn’t reach the local server. Check that it is still running.';
      }
      throw error;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
    }
  }

  function applySession(value) {
    session = value;
    ownerId = typeof value.current_owner === 'string' ? value.current_owner : value.current_owner.id;
    $('owner-select').replaceChildren(...value.owners.map((owner) => {
      const option = el('option', '', `${owner.name} · ${owner.id === 'alice' ? 'Atlas' : 'Nova'}`);
      option.value = owner.id;
      option.selected = owner.id === ownerId;
      return option;
    }));
    text('owner-avatar', ownerId === 'bob' ? 'B' : 'A');
    $('owner-avatar').classList.toggle('bob', ownerId === 'bob');
  }

  function resetForms() {
    invitationTarget = null;
    composeGrantId = null;
    pendingMessageAttempt = null;
    optionsOwner = null;
    $('invitation-form').reset();
    $('message-form').reset();
    $('meeting-options').replaceChildren();
    show($('invitation-form'), false);
    show($('message-form'), false);
    show($('message-retry-hint'), false);
  }

  function renderLoading() {
    renderKeys.clear();
    ['directory', 'permissions', 'messages', 'audit'].forEach((id) => $(id).replaceChildren(el('p', 'loading-copy', 'Loading this owner’s workspace…')));
    text('next-title', 'Getting this workspace ready…');
    text('next-description', 'Each owner has a separate view and separate approval controls.');
    show($('next-action'), false);
    text('mailbox-count', '0 MESSAGES');
    setSteps(-1);
  }

  async function refreshState(force = false) {
    if (!session || (busy && !force) || (stateController && !force)) return false;
    stateController?.abort();
    const controller = new AbortController();
    stateController = controller;
    const requestEpoch = epoch;
    const sequence = ++stateSequence;
    const expectedOwner = ownerId;
    try {
      const fresh = await requestJSON('/api/state', undefined, controller.signal);
      if (requestEpoch !== epoch || sequence !== stateSequence) return false;
      if (fresh.current_owner?.id !== expectedOwner) {
        // A different tab may have changed the shared fixture session. Never apply its data to this owner.
        state = null;
        setOnline(false);
        renderLoading();
        showError('The fixture owner changed in another tab. Reconnect to load the current owner before taking any action.', true, 'Owner changed');
        return false;
      }
      const hadConnection = online;
      state = fresh;
      setOnline(true);
      if (!hadConnection && $('error-title').textContent === 'Connection interrupted') clearError();
      renderState();
      return true;
    } catch (error) {
      if (requestEpoch !== epoch || sequence !== stateSequence || controller.signal.aborted) return false;
      setOnline(false);
      showError(`${error.message} Your last loaded state may be out of date; actions are paused.`, true, 'Connection interrupted');
      return false;
    } finally {
      if (stateController === controller) stateController = null;
      if (requestEpoch === epoch) syncControls();
    }
  }

  async function reconnect() {
    if (busy) return;
    busy = true;
    epoch += 1;
    const previousOwner = ownerId;
    stateController?.abort();
    stateController = null;
    state = null;
    renderLoading();
    syncControls();
    clearError();
    try {
      applySession(await requestJSON('/api/session'));
      if (!previousOwner || previousOwner !== ownerId) resetForms();
      await refreshState(true);
    } catch (error) {
      session = null;
      setOnline(false);
      showError(error.message, true, 'Connection interrupted');
    } finally {
      busy = false;
      syncControls();
    }
  }

  async function switchOwner(nextOwner) {
    if (busy || !session || nextOwner === ownerId) {
      if (ownerId) $('owner-select').value = ownerId;
      return;
    }
    busy = true;
    epoch += 1;
    const switchEpoch = epoch;
    stateController?.abort();
    stateController = null;
    state = null;
    resetForms();
    renderLoading();
    clearError();
    setOnline(false);
    syncControls();
    try {
      const result = await requestJSON('/api/session', { owner_id: nextOwner });
      if (switchEpoch !== epoch) return;
      applySession(result);
      await refreshState(true);
      announce(`Now viewing as ${result.owners.find((o) => o.id === ownerId)?.name || ownerId}. Unsaved form input was cleared.`);
    } catch (error) {
      // A failed response is not proof that the session change failed. Reconcile from the server.
      try {
        applySession(await requestJSON('/api/session'));
        await refreshState(true);
        showError(`${error.message} The displayed owner has been rechecked with the server.`);
      } catch (_) {
        session = null;
        ownerId = null;
        state = null;
        showError('Couldn’t confirm which fixture owner is active. Reconnect before continuing.', true, 'Connection interrupted');
      }
    } finally {
      if (switchEpoch === epoch) { busy = false; syncControls(); }
    }
  }

  async function mutate(path, payload, successMessage, callbacks = {}) {
    if (busy || !online || !state) return false;
    busy = true;
    const mutationEpoch = epoch;
    const clickedButton = document.activeElement?.matches('[data-mutation]') ? document.activeElement : null;
    const originalLabel = clickedButton?.textContent;
    if (clickedButton) clickedButton.textContent = 'Working…';
    clearError();
    announce('Applying your action…');
    syncControls();
    try {
      const result = await requestJSON(path, payload);
      if (mutationEpoch !== epoch) return false;
      callbacks.onSuccess?.(result);
      await refreshState(true);
      announce(typeof successMessage === 'function' ? successMessage(result) : successMessage);
      return true;
    } catch (error) {
      if (mutationEpoch !== epoch) return false;
      callbacks.onError?.(error);
      // Read back after every uncertain mutation. In particular, do not assume an invitation was unsent.
      await refreshState(true);
      if (online) showError(error.message + (error.code ? ` (${error.code})` : ''), false, error.uncertain ? 'Delivery wasn’t confirmed' : 'Action not completed');
      announce(error.message);
      return false;
    } finally {
      if (mutationEpoch === epoch) {
        if (clickedButton?.isConnected) clickedButton.textContent = originalLabel;
        busy = false;
        syncControls();
      }
    }
  }

  function renderPart(id, value, renderer) {
    const key = JSON.stringify(value);
    if (renderKeys.get(id) === key) return;
    const root = $(id);
    // Keep disclosures open through meaningful updates, without replacing untouched form elements.
    const opened = new Set([...root.querySelectorAll('details[open][data-detail-id]')].map((node) => node.dataset.detailId));
    const focused = root.contains(document.activeElement) ? document.activeElement : null;
    const focusKey = focused?.dataset.focusKey;
    renderer(root);
    root.querySelectorAll('details[data-detail-id]').forEach((node) => { if (opened.has(node.dataset.detailId)) node.open = true; });
    if (focusKey) [...root.querySelectorAll('[data-focus-key]')].find((node) => node.dataset.focusKey === focusKey)?.focus({ preventScroll: true });
    renderKeys.set(id, key);
  }

  function setSteps(current) {
    ['invite', 'consent', 'propose', 'approve'].forEach((name, index) => {
      const step = $(`step-${name}`);
      step.classList.toggle('done', index < current);
      step.classList.toggle('current', index === current);
      if (index === current) step.setAttribute('aria-current', 'step');
      else step.removeAttribute('aria-current');
      step.querySelector('.step-number').textContent = index < current ? '✓' : String(index + 1);
    });
  }

  function scrollToSection(id) { $(id).scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'instant' : 'smooth', block: 'start' }); }
  function configureNext(title, description, label, action, step, eyebrow = 'YOUR NEXT MOVE') {
    text('next-title', title);
    text('next-description', description);
    text('next-eyebrow', eyebrow);
    nextAction = action;
    text('next-action', label || '');
    show($('next-action'), !!label);
    setSteps(step);
  }

  function renderNext() {
    const incomingInvitation = newest(state.invitations).find((i) => i.status === 'pending' && ownerOfAgent(i.to_agent) === ownerId);
    const incomingProposal = newest(state.messages).find((m) => m.status === 'awaiting_approval' && ownerOfAgent(m.recipient) === ownerId);
    const awaitingProposal = newest(state.messages).find((m) => m.status === 'awaiting_approval');
    const queued = newest(state.messages).find((m) => m.status === 'queued');
    const outgoingInvitation = newest(state.invitations).find((i) => i.status === 'pending');
    const active = newest(state.grants).find((g) => g.status === 'active' && g.turns_used < g.max_turns);
    const approved = newest(state.messages).find((m) => m.status === 'approved');
    if (incomingProposal) {
      configureNext('A proposal is ready. You have the final say.', `${nameOfAgent(incomingProposal.recipient)} selected a sample time. Review the proposal and approve or decline it yourself.`, 'Review proposal ↓', () => scrollToSection('mailbox-section'), 3);
    } else if (incomingInvitation) {
      configureNext(`${firstName(ownerOfAgent(incomingInvitation.from_agent))} is asking to connect.`, 'Review the purpose, scope, time limit, and request budget before opening the door.', 'Review invitation ↓', () => scrollToSection('consent-section'), 1);
    } else if (awaitingProposal) {
      const recipientOwner = ownerOfAgent(awaitingProposal.recipient);
      configureNext(`The next move belongs to ${firstName(recipientOwner)}.`, 'The mock agent has proposed one time. The recipient owner must approve it; agents cannot approve for them.', `View as ${firstName(recipientOwner)} →`, () => switchOwner(recipientOwner), 3);
    } else if (queued) {
      configureNext('Your request is in the local queue.', 'The dispatcher will recheck the grant and ask the mock recipient to compare the public options. This view refreshes every two seconds.', null, null, 2);
    } else if (outgoingInvitation) {
      const recipientOwner = ownerOfAgent(outgoingInvitation.to_agent);
      configureNext(`Invitation sent. ${firstName(recipientOwner)} decides next.`, 'No message can pass until the recipient accepts. Switch demo owners to see their consent desk.', `View as ${firstName(recipientOwner)} →`, () => switchOwner(recipientOwner), 1);
    } else if (approved) {
      const senderGrant = state.grants.find((g) => g.id === approved.grant_id);
      const canCompose = senderGrant?.status === 'active' && senderGrant.turns_used < senderGrant.max_turns && ownerOfAgent(senderGrant.from_agent) === ownerId;
      configureNext('A shared result, with a receipt.', 'The recipient owner approved a time. Both owners can inspect the same receipt. No calendar event was created.', canCompose ? 'Send another request' : 'View receipt ↓', canCompose ? () => openComposer(senderGrant.id) : () => scrollToSection('mailbox-section'), 4, 'COORDINATION COMPLETE');
    } else if (active) {
      const senderOwner = ownerOfAgent(active.from_agent);
      if (senderOwner === ownerId) configureNext('Permission granted. Send a few options.', `${nameOfAgent(active.from_agent)} can send scoped meeting requests to ${nameOfAgent(active.to_agent)} until this grant expires or is revoked.`, 'Compose request →', () => openComposer(active.id), 2);
      else configureNext('The connection is open, within your limits.', `${nameOfAgent(active.from_agent)} may now send a meeting proposal. Switch back to the sender owner to try it.`, `View as ${firstName(senderOwner)} →`, () => switchOwner(senderOwner), 2);
    } else {
      const partner = otherAgent();
      configureNext('Start with a simple introduction.', `Ask ${partner?.name || 'the other agent'}’s owner for permission to coordinate a meeting. Nothing gets sent between agents until they agree.`, 'Request permission →', () => openInvitation(partner?.id), 0);
    }
  }

  function renderDirectory(root) {
    root.replaceChildren();
    const own = myAgent();
    const agents = [...state.agents].sort((a, b) => Number(b.id === own?.id) - Number(a.id === own?.id));
    for (const agent of agents) {
      const isOwn = agent.owner_id === ownerId;
      const card = el('article', `agent-card${isOwn ? ' own' : ''}`);
      const top = el('div', 'agent-topline');
      top.append(el('span', `agent-avatar ${agent.id}`, agent.name.slice(0, 1).toLowerCase()), el('span', `agent-role${isOwn ? ' own-role' : ''}`, isOwn ? 'YOUR AGENT' : 'ANOTHER OWNER'));
      card.append(top, el('h3', '', agent.name), el('p', 'agent-owner', `Owned by ${firstName(agent.owner_id)}`), el('p', 'agent-description', agent.description), el('p', 'agent-provider', agent.provider));
      if (isOwn) card.append(el('p', 'agent-id', `@${agent.id} · Owner-controlled fixture`));
      else {
        const pending = state.invitations.find((i) => i.from_agent === own?.id && i.to_agent === agent.id && i.status === 'pending');
        const active = state.grants.find((g) => g.from_agent === own?.id && g.to_agent === agent.id && g.status === 'active');
        const button = actionButton(pending ? 'Invitation pending' : active ? 'View permission ↓' : 'Request permission', () => pending || active ? scrollToSection('consent-section') : openInvitation(agent.id), { variant: 'quiet', action: 'invite', entityId: agent.id });
        if (pending) button.dataset.unavailable = 'true';
        button.dataset.focusKey = `directory-${agent.id}`;
        card.append(button);
      }
      const details = el('details');
      details.dataset.detailId = `key-${agent.id}`;
      details.append(el('summary', '', 'Fixture key fingerprint'), el('p', '', agent.fingerprint));
      card.append(details);
      root.append(card);
    }
  }

  function emptyState(title, description, symbol = '◇', compact = false) {
    const empty = el('div', `empty-state${compact ? ' compact' : ''}`);
    const mark = el('span', 'empty-symbol', symbol);
    mark.setAttribute('aria-hidden', 'true');
    empty.append(mark, el('h3', '', title), el('p', '', description));
    return empty;
  }

  function invitationCard(invitation) {
    const incoming = ownerOfAgent(invitation.to_agent) === ownerId;
    const card = el('article', `consent-item${incoming ? ' incoming' : ''}`);
    card.dataset.invitationId = invitation.id;
    const top = el('div', 'card-topline');
    top.append(el('h3', '', route(invitation.from_agent, invitation.to_agent)), badge(invitation.status));
    card.append(top, el('p', 'item-purpose', invitation.purpose), el('span', 'scope-tag', invitation.scope));
    card.append(el('p', 'item-meta', `${invitation.max_turns} request turns · Expires ${stamp(invitation.expires_at)}`));
    const actions = el('div', 'card-actions');
    if (incoming) {
      card.append(el('p', 'consent-helper', 'Accepting allows only the named sender to send meeting proposals. It does not approve a meeting. Either owner can revoke.'));
      actions.append(
        actionButton('Accept invitation', () => mutate(apiPath('invitations', invitation.id, 'accept'), {}, 'Invitation accepted. A scoped grant is active.'), { variant: 'dark', action: 'accept-invitation', entityId: invitation.id }),
        actionButton('Decline', () => mutate(apiPath('invitations', invitation.id, 'decline'), {}, 'Invitation declined. No grant was created.'), { action: 'decline-invitation', entityId: invitation.id })
      );
    } else {
      const recipientOwner = ownerOfAgent(invitation.to_agent);
      card.append(el('p', 'consent-helper', `Waiting for ${firstName(recipientOwner)}’s consent. No agent messages are authorized yet.`));
      const button = actionButton(`View as ${firstName(recipientOwner)} →`, () => switchOwner(recipientOwner), { variant: 'quiet', action: 'switch-owner', entityId: recipientOwner });
      button.dataset.ownerSwitch = recipientOwner;
      actions.append(button);
    }
    card.append(actions);
    return card;
  }

  function grantCard(grant) {
    const card = el('article', `consent-item ${grant.status}`);
    card.dataset.grantId = grant.id;
    const top = el('div', 'card-topline');
    top.append(el('h3', '', route(grant.from_agent, grant.to_agent)), badge(grant.status));
    card.append(top, el('span', 'scope-tag', grant.scope));
    const meta = el('dl', 'grant-meta');
    for (const [term, value, className] of [
      ['Request budget', `${Math.max(0, grant.max_turns - grant.turns_used)} of ${grant.max_turns} left`, ''],
      ['Expires (UTC)', stamp(grant.expires_at).replace(' UTC', ''), ''],
      ['Per-request limits', `${grant.rate_per_minute} / minute per agent pair · Up to ${Math.round(grant.ttl_seconds / 60)} min lifetime`, 'full']
    ]) {
      const group = el('div', className);
      group.append(el('dt', '', term), el('dd', '', value));
      meta.append(group);
    }
    card.append(meta);
    if (grant.status === 'active') {
      const actions = el('div', 'card-actions');
      if (ownerOfAgent(grant.from_agent) === ownerId) {
        const retryAvailable = pendingMessageAttempt?.grantId === grant.id;
        const compose = actionButton(retryAvailable ? 'Retry request' : grant.turns_used < grant.max_turns ? 'Compose request' : 'Budget used', () => openComposer(grant.id), { variant: 'dark', action: 'compose', entityId: grant.id });
        if (grant.turns_used >= grant.max_turns && !retryAvailable) compose.dataset.unavailable = 'true';
        actions.append(compose);
      }
      actions.append(actionButton('Revoke', () => mutate(apiPath('grants', grant.id, 'revoke'), {}, 'Grant revoked. Unapproved requests are cancelled.', { onSuccess: () => { if (composeGrantId === grant.id) closeComposer(); } }), { variant: 'danger', action: 'revoke-grant', entityId: grant.id }));
      card.append(actions, el('p', 'consent-helper', 'Revoking also cancels queued and unapproved requests. Completed receipts remain.'));
    } else card.append(el('p', 'consent-helper', 'This grant no longer allows new messages or approvals.'));
    return card;
  }

  function renderPermissions(root) {
    root.replaceChildren();
    const pending = newest(state.invitations).filter((i) => i.status === 'pending');
    const active = newest(state.grants).filter((g) => g.status === 'active');
    pending.forEach((i) => root.append(invitationCard(i)));
    active.forEach((g) => root.append(grantCard(g)));
    if (!pending.length && !active.length) root.append(emptyState('The door is closed.', 'No active permission to send a message. Start a fresh connection from the directory.', '◇', true));
    const oldGrants = newest(state.grants).filter((g) => g.status !== 'active');
    const oldInvites = newest(state.invitations).filter((i) => !['pending', 'accepted'].includes(i.status));
    if (oldGrants.length || oldInvites.length) {
      const details = el('details', 'history-details');
      details.dataset.detailId = 'permission-history';
      details.append(el('summary', '', `Past permissions (${oldGrants.length + oldInvites.length})`));
      oldGrants.forEach((g) => details.append(grantCard(g)));
      oldInvites.forEach((i) => {
        const row = el('div', 'history-row');
        row.append(el('span', '', route(i.from_agent, i.to_agent)), badge(i.status));
        details.append(row);
      });
      root.append(details);
    }
  }

  function messageCard(message) {
    const recipientOwns = ownerOfAgent(message.recipient) === ownerId;
    const card = el('article', `message-card ${message.status}`);
    card.dataset.messageId = message.id;
    card.append(el('p', 'message-route', `${route(message.sender, message.recipient)} · ${stamp(message.created_at)}`));
    const top = el('div', 'card-topline');
    top.append(el('h3', '', message.payload.title), badge(message.status));
    card.append(top);
    const descriptions = {
      queued: 'Signed and queued. The local dispatcher is checking permission before the mock recipient wakes.',
      awaiting_approval: recipientOwns ? 'Your agent compared the sample options. You choose whether to approve its proposal.' : `Waiting for ${firstName(ownerOfAgent(message.recipient))} to review the proposed time.`,
      approved: 'The recipient owner approved this proposal. Both owners see the same result.',
      declined: 'The recipient owner declined this proposal. No time was approved.',
      cancelled: 'Cancelled because permission was withdrawn. No further agent work or approval is allowed.',
      expired: 'This request expired before coordination finished. Send a fresh request if the grant still allows it.',
      rejected: 'The local dispatcher rejected this request. No approval was recorded.'
    };
    card.append(el('p', 'message-description', descriptions[message.status] || ''));
    const options = el('ul', 'message-options');
    for (const option of message.payload.options) {
      const selected = sameOption(option, message.proposal?.selected_option);
      const row = el('li', selected ? 'selected' : '');
      const marker = el('span', 'option-marker', selected ? '✓' : '○');
      marker.setAttribute('aria-hidden', 'true');
      row.append(marker, el('span', '', optionText(option) + (selected ? ' · Proposed' : '')));
      options.append(row);
    }
    card.append(options);
    if (message.proposal && message.status === 'awaiting_approval') {
      const proposal = el('div', 'proposal-box');
      proposal.append(el('p', 'eyebrow', `${nameOfAgent(message.recipient).toUpperCase()}’S LOCAL PROPOSAL`), el('strong', '', optionText(message.proposal.selected_option)), el('p', '', message.proposal.explanation));
      card.append(proposal);
      if (recipientOwns) {
        const actions = el('div', 'card-actions');
        actions.append(
          actionButton('Approve proposal', () => mutate(apiPath('messages', message.id, 'approve'), {}, 'Proposal approved. A shared receipt was created; no calendar event was booked.'), { variant: 'dark', action: 'approve-message', entityId: message.id }),
          actionButton('Decline proposal', () => mutate(apiPath('messages', message.id, 'decline'), {}, 'Proposal declined.'), { action: 'decline-message', entityId: message.id })
        );
        card.append(actions, el('p', 'field-help', 'This records your demo decision only. It never creates a calendar event.'));
      }
    }
    if (['queued', 'awaiting_approval'].includes(message.status)) card.append(el('p', 'message-footnote', `Request expires ${stamp(message.expires_at)}. Permission is checked again before approval.`));
    if (message.failure_code) card.append(el('p', 'message-footnote', `Reason: ${message.failure_code}`));
    if (message.receipt) card.append(receiptCard(message.receipt));
    return card;
  }

  function receiptCard(receipt) {
    const receiptBox = el('div', 'receipt-box');
    receiptBox.append(el('p', 'eyebrow', 'SHARED RESULT RECEIPT'), el('strong', '', receipt.decision === 'approved' ? optionText(receipt.selected_option) : 'Proposal declined'), el('p', '', `Decision recorded ${stamp(receipt.decided_at)}. No calendar booking was made.`));
    const details = el('details');
    details.dataset.detailId = `receipt-${receipt.id}`;
    details.append(el('summary', '', 'Inspect immutable receipt'));
    const values = el('dl');
    for (const [key, value] of [['Receipt ID', receipt.id], ['Message ID', receipt.message_id], ['Decision', receipt.decision], ['Fixture signature', receipt.signature]]) values.append(el('dt', '', key), el('dd', '', value));
    details.append(values);
    receiptBox.append(details);
    return receiptBox;
  }

  function renderMessages(root) {
    root.replaceChildren();
    text('mailbox-count', `${state.messages.length} ${state.messages.length === 1 ? 'MESSAGE' : 'MESSAGES'}`);
    if (!state.messages.length) root.append(emptyState('No conversations yet.', 'Start with an invitation. After the other owner accepts, send a few times to compare.', '↔'));
    else newest(state.messages).forEach((message) => root.append(messageCard(message)));
  }

  function renderAudit(root) {
    root.replaceChildren();
    if (!state.audit.length) { root.append(el('p', 'quiet-copy', 'Activity appears here as each step happens. Every invitation, grant, and decision leaves a trace.')); return; }
    const list = el('ol', 'audit-list');
    for (const event of [...state.audit].sort((a, b) => b.occurred_at - a.occurred_at || Number(b.id) - Number(a.id)).slice(0, 8)) {
      const item = el('li', 'audit-item');
      const body = el('div');
      const raw = String(event.event);
      const eventName = auditNames[raw] || raw.replaceAll('_', ' ').replaceAll('.', ' ').replace(/^\w/, (s) => s.toUpperCase());
      body.append(el('span', '', eventName));
      const actor = state.owners.find((o) => o.id === event.actor_id)?.name || state.agents.find((a) => a.id === event.actor_id)?.name || event.actor_id;
      body.append(el('small', '', `${actor || 'Local dispatcher'} · ${String(event.entity_id).slice(0, 16)}`));
      const time = el('time', '', clockTime(event.occurred_at));
      time.dateTime = new Date(event.occurred_at * 1000).toISOString();
      time.title = stamp(event.occurred_at);
      item.append(body, time);
      list.append(item);
    }
    root.append(list, el('p', 'field-help', 'Latest 8 events · All times UTC'));
  }

  function renderState() {
    if (!state) return;
    renderPart('directory', [ownerId, state.agents, state.invitations, state.grants], renderDirectory);
    renderPart('permissions', [ownerId, state.invitations, state.grants, pendingMessageAttempt?.key || null], renderPermissions);
    renderPart('messages', [ownerId, state.messages], renderMessages);
    renderPart('audit', [ownerId, state.audit], renderAudit);
    renderNext();
    if (invitationTarget) {
      const existing = state.invitations.some((i) => i.status === 'pending' && i.from_agent === myAgent()?.id && i.to_agent === invitationTarget);
      const granted = state.grants.some((g) => g.status === 'active' && g.from_agent === myAgent()?.id && g.to_agent === invitationTarget);
      if (existing || granted) closeInvitation();
    }
    if (composeGrantId) {
      const grant = state.grants.find((g) => g.id === composeGrantId);
      if (!grant || grant.status !== 'active' || ownerOfAgent(grant.from_agent) !== ownerId || (grant.turns_used >= grant.max_turns && !pendingMessageAttempt)) {
        closeComposer();
        announce('The composer closed because this grant no longer allows a new request.');
      } else updateComposerScope(grant);
    }
    syncControls();
  }

  function openInvitation(agentId) {
    if (busy || !online || !state) return;
    invitationTarget = agentId;
    const target = agentById(agentId);
    text('invitation-form-title', `Ask ${target.name}’s owner to connect`);
    text('invitation-explainer', `${firstName(target.owner_id)} must accept before ${myAgent().name} can send any message. Either owner can revoke the grant.`);
    show($('invitation-form'), true);
    scrollToSection('directory-section');
    $('invitation-purpose').focus({ preventScroll: true });
  }
  function closeInvitation() { invitationTarget = null; show($('invitation-form'), false); }

  function buildOptions() {
    $('meeting-options').replaceChildren();
    const options = state.suggested_options.slice(0, state.limits?.max_options || 3);
    options.forEach((option, index) => {
      const label = el('label', 'option-row');
      const input = el('input');
      input.type = 'checkbox';
      input.name = 'meeting-option';
      input.value = String(index);
      input.checked = true;
      input.dataset.start = option.start;
      input.dataset.duration = String(option.duration_minutes);
      input.addEventListener('change', invalidateChangedMessageIntent);
      const content = el('span');
      content.append(el('span', '', optionText(option)), el('small', '', `${option.duration_minutes} minutes · Public sample option`));
      label.append(input, content);
      $('meeting-options').append(label);
    });
    optionsOwner = ownerId;
  }
  function updateComposerScope(grant) {
    text('composer-route', `${route(grant.from_agent, grant.to_agent)} · meeting.coordinate`);
    text('composer-scope', `One request uses one turn. ${Math.max(0, grant.max_turns - grant.turns_used)} of ${grant.max_turns} turns remain. This request expires within ${Math.round(grant.ttl_seconds / 60)} minutes and requires the recipient owner’s approval.`);
  }
  function openComposer(grantId) {
    if (busy || !online || !state) return;
    const grant = state.grants.find((g) => g.id === grantId);
    if (!grant || grant.status !== 'active' || ownerOfAgent(grant.from_agent) !== ownerId || (grant.turns_used >= grant.max_turns && pendingMessageAttempt?.grantId !== grant.id)) return;
    composeGrantId = grantId;
    if (optionsOwner !== ownerId || !$('meeting-options').children.length) buildOptions();
    invalidateChangedMessageIntent();
    updateComposerScope(grant);
    show($('message-form'), true);
    show($('message-retry-hint'), !!pendingMessageAttempt);
    scrollToSection('mailbox-section');
    $('meeting-title').focus({ preventScroll: true });
  }
  function closeComposer() { composeGrantId = null; show($('message-form'), false); }
  function currentMessagePayload() {
    return {
      grant_id: composeGrantId,
      title: $('meeting-title').value.trim(),
      options: [...$('meeting-options').querySelectorAll('input:checked')].map((input) => ({ start: input.dataset.start, duration_minutes: Number(input.dataset.duration) }))
    };
  }
  function invalidateChangedMessageIntent() {
    if (pendingMessageAttempt && JSON.stringify(currentMessagePayload()) !== pendingMessageAttempt.signature) {
      pendingMessageAttempt = null;
      show($('message-retry-hint'), false);
    }
  }
  function newRequestKey() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  $('owner-select').addEventListener('change', (event) => switchOwner(event.target.value));
  $('next-action').addEventListener('click', () => { if (!busy && online) nextAction?.(); });
  $('retry-connection').addEventListener('click', reconnect);
  $('dismiss-error').addEventListener('click', clearError);
  $('close-invitation').addEventListener('click', closeInvitation);
  $('close-composer').addEventListener('click', closeComposer);
  $('meeting-title').addEventListener('input', invalidateChangedMessageIntent);

  $('invitation-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!invitationTarget || !state || busy) return;
    const purpose = $('invitation-purpose').value.trim();
    if (!purpose) { $('invitation-purpose').setCustomValidity('Add a short purpose for this connection.'); $('invitation-purpose').reportValidity(); return; }
    await mutate('/api/invitations', { from_agent: myAgent().id, to_agent: invitationTarget, purpose, max_turns: 4, expires_in: 3600 }, 'Invitation sent. The recipient owner must now accept.', { onSuccess: closeInvitation });
  });
  $('invitation-purpose').addEventListener('input', () => $('invitation-purpose').setCustomValidity(''));

  $('message-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    if (!composeGrantId || !state || busy) return;
    const payload = currentMessagePayload();
    if (!payload.title) { $('meeting-title').setCustomValidity('Add a meeting title.'); $('meeting-title').reportValidity(); return; }
    if (!payload.options.length || payload.options.length > (state.limits?.max_options || 3)) { showError('Choose between one and three sample time options.'); return; }
    const signature = JSON.stringify(payload);
    if (!pendingMessageAttempt || pendingMessageAttempt.signature !== signature) pendingMessageAttempt = { signature, key: newRequestKey(), grantId: payload.grant_id };
    await mutate('/api/messages', { ...payload, idempotency_key: pendingMessageAttempt.key }, (result) => result.duplicate ? 'The existing request was recovered. No duplicate message was created.' : 'Meeting request signed and queued for the mock recipient.', {
      onSuccess: () => { pendingMessageAttempt = null; closeComposer(); show($('message-retry-hint'), false); },
      onError: (error) => { show($('message-retry-hint'), !!error.uncertain); }
    });
  });
  $('meeting-title').addEventListener('input', () => $('meeting-title').setCustomValidity(''));

  window.addEventListener('online', () => { if (!busy) session ? refreshState(true) : reconnect(); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden && !busy && session) refreshState(true); });
  window.setInterval(() => { if (!document.hidden && !busy && session) refreshState(); }, 2000);
  reconnect();
})();
