// Paint the point field once; each frame only moves the lock halves, key and orbits.
function makeLock() {
  const sprite = document.createElement('canvas');
  sprite.width = sprite.height = 640;
  const ink = sprite.getContext('2d');
  ink.translate(320, 320);
  ink.scale(2, 2);
  const radius = 142;
  const halo = ink.createRadialGradient(-25, -35, 5, 0, 0, radius);
  halo.addColorStop(0, '#253015');
  halo.addColorStop(0.85, '#131b12');
  halo.addColorStop(1, '#161e14');
  ink.fillStyle = halo;
  ink.beginPath();
  ink.arc(0, 0, radius, 0, Math.PI * 2);
  ink.fill();
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < 7800; i++) {
    const z = (i + 0.5) / 7800;
    const radial = radius * Math.sqrt(1 - z * z);
    const x = radial * Math.cos(i * goldenAngle);
    const y = radial * Math.sin(i * goldenAngle);
    const light = Math.max(0, (-x - y) / (radius * 2));
    ink.fillStyle = i % 4 === 0 ? '#c5ff42' : '#d1dfac';
    ink.globalAlpha = 0.18 + light * 0.65 + (1 - z) * 0.16;
    ink.fillRect(x, y, 0.65 + light, 0.65 + light);
  }
  const hole = new Path2D();
  hole.arc(0, -22, 35, 1.18, Math.PI * 2 + 1.96, true);
  hole.lineTo(-28, 68);
  hole.lineTo(28, 68);
  hole.closePath();
  ink.globalAlpha = 1;
  ink.shadowColor = '#a2ee26';
  ink.shadowBlur = 16;
  ink.strokeStyle = '#b4ed44';
  ink.lineWidth = 2.1;
  ink.stroke(hole);
  ink.shadowBlur = 0;
  ink.fillStyle = '#0a100b';
  ink.fill(hole);
  return sprite;
}

function makeKey() {
  const sprite = document.createElement('canvas');
  sprite.width = 360;
  sprite.height = 148;
  const ink = sprite.getContext('2d');
  ink.scale(2, 2);
  ink.translate(6, 37);
  const key = new Path2D();
  key.moveTo(0, -4); key.lineTo(108, -4);
  key.arc(133, 0, 25, Math.PI + 0.16, Math.PI * 3 - 0.16);
  key.lineTo(48, 4); key.lineTo(48, 15); key.lineTo(40, 15);
  key.lineTo(40, 4); key.lineTo(25, 4); key.lineTo(25, 20);
  key.lineTo(16, 20); key.lineTo(16, 4); key.lineTo(0, 4); key.closePath();
  key.moveTo(150, 0); key.arc(133, 0, 17, 0, Math.PI * 2);
  ink.fillStyle = '#516c18';
  ink.fill(key, 'evenodd');
  ink.strokeStyle = '#c2ff32';
  ink.shadowColor = '#adf932';
  ink.shadowBlur = 8;
  ink.lineWidth = 1.4;
  ink.stroke(key);
  ink.shadowBlur = 0;
  ink.clip(key, 'evenodd');
  ink.fillStyle = '#ddff86';
  for (let i = 0; i < 6800; i++) {
    ink.fillRect((i * 59.724) % 160, (i * 37.463) % 54 - 27, 0.65, 0.65);
  }
  return sprite;
}

const orbits = [
  { tilt: 0.26, period: 3.5, direction: -1, color: '#c6cdbd', dot: 0.8 },
  { tilt: -0.31, period: 2.9, direction: 1, color: '#c7dd98', dot: 0.7 },
  { tilt: -0.88, period: 2.4, direction: 1, color: '#b5ed45', dot: 1.05 }
];

function ease(from, to, value) {
  const t = Math.max(0, Math.min(1, (value - from) / (to - from)));
  return t * t * (3 - 2 * t);
}

export function startGimbal(canvas) {
  const ctx = canvas.getContext('2d');
  if (!ctx) return { unlock: async () => {}, stop() {} };
  const lock = makeLock(), key = makeKey();
  const motion = matchMedia('(prefers-reduced-motion: reduce)');
  let frame = 0, angle = 0, grab = null, started = null, finish, reveal, stopped = false;

  function draw(now) {
    frame = 0;
    const { width, height } = canvas.getBoundingClientRect();
    const ratio = Math.min(devicePixelRatio || 1, 2);
    const w = Math.max(1, Math.round(width * ratio)), h = Math.max(1, Math.round(height * ratio));
    if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
    const progress = started === null ? 0 : motion.matches ? 1 : Math.min(1, (now - started) / 1350);
    const insert = ease(0, 0.4, progress), turn = ease(0.37, 0.68, progress);
    const open = ease(0.66, 0.95, progress);
    if (progress >= 0.66 && reveal) {
      reveal();
      reveal = null;
    }
    ctx.resetTransform();
    ctx.clearRect(0, 0, w, h);
    ctx.translate(w / 2, h / 2);
    const scale = Math.min(w / 530, h / 415);
    ctx.scale(scale, scale);
    ctx.translate(-33, -5);
    const opacity = 1 - ease(0.86, 1, progress);
    ctx.globalAlpha = opacity;
    const seconds = motion.matches ? 0 : now / 1000;
    ctx.save();
    ctx.rotate(-0.10 + turn * 0.23);
    for (const side of [-1, 1]) {
      ctx.save();
      ctx.translate(side * open * 67, -open * 4);
      ctx.rotate(side * open * 0.12);
      ctx.drawImage(lock, side < 0 ? 0 : 320, 0, 320, 640, side < 0 ? -160 : 0, -160, 160, 320);
      ctx.restore();
    }
    ctx.restore();
    for (const { tilt, period, direction, color, dot } of orbits) {
      ctx.save();
      const travel = angle + direction * seconds * Math.PI * 2 / period;
      ctx.rotate(tilt + Math.sin(angle + seconds * 0.65) * 0.16);
      ctx.fillStyle = color;
      for (let i = 0; i < 150; i++) {
        const a = i * Math.PI / 75 + travel;
        const x = Math.cos(a) * (177 + open * 32), y = Math.sin(a) * (54 + open * 22);
        if (Math.sin(a) < 0 && x * x + y * y < 142 * 142) continue;
        // Two leading lights per orbit leave a short taper of brighter particles.
        const behind = (150 - direction * i) % 75;
        const trail = Math.max(0, 1 - behind / 11) ** 2;
        ctx.globalAlpha = (0.65 + 0.35 * trail) * opacity;
        ctx.beginPath(); ctx.arc(x, y, dot + 1.8 * trail, 0, Math.PI * 2); ctx.fill();
      }
      ctx.restore();
    }
    ctx.translate(58 * (1 - insert), 27 * (1 - insert) - 16 * insert);
    ctx.rotate(0.45 - 0.15 * insert + 0.36 * turn);
    ctx.scale(1 - 0.30 * insert, 1 - 0.82 * Math.sin(turn * Math.PI * 0.65));
    ctx.drawImage(key, -6, -37, 180, 74);
    ctx.globalAlpha = 1;
    if (progress >= 1) { finish?.(); finish = null; return; }
    if (!stopped && !motion.matches) frame = requestAnimationFrame(draw);
  }

  function refresh() {
    cancelAnimationFrame(frame);
    if (!stopped) draw(performance.now());
  }
  function down(e) { if (started === null) { grab = e.clientX; canvas.setPointerCapture(e.pointerId); } }
  function move(e) {
    if (grab === null || started !== null) return;
    angle += (e.clientX - grab) * 0.012;
    grab = e.clientX;
    if (motion.matches) refresh();
  }
  function up() { grab = null; }
  canvas.addEventListener('pointerdown', down);
  canvas.addEventListener('pointermove', move);
  canvas.addEventListener('lostpointercapture', up);
  motion.addEventListener('change', refresh);
  const observer = new ResizeObserver(refresh);
  observer.observe(canvas);
  refresh();
  return {
    unlock(onOpen) {
      if (motion.matches || stopped) return Promise.resolve();
      reveal = onOpen;
      started = performance.now();
      return new Promise(resolve => { finish = resolve; refresh(); });
    },
    stop() {
      stopped = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      motion.removeEventListener('change', refresh);
      canvas.removeEventListener('pointerdown', down);
      canvas.removeEventListener('pointermove', move);
      canvas.removeEventListener('lostpointercapture', up);
    }
  };
}
