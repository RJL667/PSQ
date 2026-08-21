import { useState } from 'react';
import { parseCurrency, sanitizeCurrencyInput } from '../lib/format.js';

// Currency text input — mirrors the legacy formatCurrencyInput/stripCurrencyInput:
// shows the grouped value ("R29 308 000", en-ZA spaces) when blurred, and the raw
// text as typed when focused for easy editing. Calls onChange(cleanedString),
// which may still contain separators — callers store it verbatim and let
// parseCurrency interpret it. Percent fields (discounts) do NOT use this — only
// rand amounts.
export default function CurrencyInput({ value, onChange, prefix = 'R', ...rest }) {
  const [focused, setFocused] = useState(false);
  const num = parseCurrency(value);
  const display = focused ? (value ?? '') : num > 0 ? prefix + num.toLocaleString('en-ZA', { maximumFractionDigits: 2 }) : '';
  return (
    <input
      {...rest}
      value={display}
      onFocus={() => setFocused(true)}
      onBlur={() => setFocused(false)}
      // Keep separators: stripping every non-digit here silently deleted the
      // decimal point, turning "57 096.00" into 5 709 600. parseCurrency decides
      // what the separators mean; this only removes noise (R, spaces, letters).
      onChange={(e) => onChange(sanitizeCurrencyInput(e.target.value))}
    />
  );
}
