import {clsx} from 'clsx';

export function renderNotice(element, message, urgent) {
  element.className = clsx('notice', {'notice--urgent': urgent});
  element.textContent = message;
}
