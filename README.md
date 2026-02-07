# UniFi Scripts

These are my personal UniFi scripts.

They’re mostly things I’ve written to automate bits of **UniFi Network / UniFi OS**, or to avoid clicking through the UI when I don’t need to.

---

## Scripts

| Script | Platform | Description |
|-------|----------|-------------|
| `unifi-portforward.ps1` | PowerShell | Create UniFi Network port forward (NAT) rules |
| `unifi-portforward.sh`  | Bash | Same thing, minimal dependencies |

More scripts will likely appear over time.

---

## How I write these

- **Parameters live at the top of the file**  
  You shouldn’t have to dig through logic just to make a script work.

- **UI-accurate behaviour**  
  Scripts aim to behave the same way the UniFi UI does.

- **Minimal dependencies**  
  I try not to require extra tooling unless it’s genuinely needed.

---

## Notes

- These scripts use undocumented UniFi APIs  
- UniFi updates can and will break things  
- Test before using anywhere important

---

## Contributions

Hope these are useful.

If you want to add something or improve what’s here, feel free.  
If not, no worries — use whatever helps.
