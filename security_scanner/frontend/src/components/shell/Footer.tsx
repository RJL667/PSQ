import styles from './Footer.module.css'

/** Quiet legal footer line (spec §32) — never inside a large panel. */
export default function Footer() {
  return (
    <footer className={styles.footer}>
      <span>Passive external assessment only • No intrusive testing • For insurance underwriting use</span>
      <span className={styles.org}>PHISHIELD UMA (Pty) Ltd • Authorised Financial Services Provider • FSP 46418</span>
    </footer>
  )
}
