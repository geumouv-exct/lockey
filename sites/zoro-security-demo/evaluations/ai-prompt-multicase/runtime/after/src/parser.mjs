const decimal = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/;

export function parseValue(req) {
  const input = req.body?.value;
  const value = typeof input === 'string' ? input.trim() : input;

  if (typeof value !== 'number' && (typeof value !== 'string' || !decimal.test(value))) {
    throw new TypeError('Expected a decimal number');
  }

  const number = Number(value);
  if (!Number.isFinite(number) || Math.abs(number) > Number.MAX_SAFE_INTEGER) {
    throw new RangeError('Number is out of range');
  }

  return number;
}
