/* Local visual simulation only. No network, storage, accounts, or real messages. */
(() => {
  'use strict';
  const root = document.getElementById('journey');
  const invite = document.getElementById('invite');
  const consent = document.getElementById('consent');
  const reset = document.getElementById('reset');
  const announcer = document.getElementById('announcer');
  const description = document.getElementById('description');
  const setDescription = text => { if (description) description.textContent = text; };
  if (!root || !invite || !consent || !reset || !announcer) return;
  let timer = null;
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const announce = text => { announcer.textContent = text; };
  const ready = () => {
    window.clearTimeout(timer);
    timer = null;
    root.dataset.phase = 'ready';
    invite.disabled = false;
    consent.disabled = true;
    reset.disabled = true;
    setDescription('A quiet path between agents.\nTap the plane. No live messages.');
    announce('Simulation reset. Start a fictional connection request. No live messages.');
  };
  invite.addEventListener('click', () => {
    if (root.dataset.phase !== 'ready') return;
    root.dataset.phase = 'invited';
    invite.disabled = true;
    consent.disabled = false;
    reset.disabled = false;
    announce('Fictional request waiting at the boundary. Approve at the receiving gate to continue, or reset to decline. No access has been granted.');
    setDescription('Permission comes first.\nTap the lock. No live messages.');
    consent.focus();
  });
  consent.addEventListener('click', () => {
    if (root.dataset.phase !== 'invited') return;
    root.dataset.phase = 'crossing';
    consent.disabled = true;
    announce('Simulated permission granted for one fictional message. Nothing is sent outside this page.');
    setDescription('Permission given. A clear path.\nLocal demo. Nothing is sent.');
    reset.focus();
    timer = window.setTimeout(() => {
      root.dataset.phase = 'complete';
      timer = null;
      setDescription('A message received. A decision remembered.\nJust a demo. Nothing was sent.');
      announce('Fictional message received. The check mark is a local demo receipt, not a real delivery or completed task. Reset to try again.');
    }, reducedMotion.matches ? 0 : 1500);
  });
  reset.addEventListener('click', () => { ready(); invite.focus(); });
  ready();
})();
