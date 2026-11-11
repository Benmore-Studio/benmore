// SIGN-SOURCE-ONLY: a `run: compute` module. Server code that has to live
// under static/, and must not be served from it.
import { KEY } from './key'

export function sign(): string {
  return 'signed:' + KEY
}
