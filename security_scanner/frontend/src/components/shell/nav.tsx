import {
  LayoutDashboard, FileText, Presentation, FileCode2, Gauge, Coins, Radar,
  Bug, ShieldCheck, ClipboardCheck, ScrollText, Flag, Wrench, History,
  Plug, Settings, Lock, Mail, Network, Eye, Cpu, Search,
  type LucideIcon,
} from 'lucide-react'

export interface NavItem {
  label: string
  to?: string
  /** report type for the PDF endpoint instead of an in-app route */
  report?: 'summary' | 'assessment' | 'full' | 'raw'
  icon: LucideIcon
  disabled?: boolean
}

export interface NavGroup {
  label: string
  items: NavItem[]
}

export const NAV: NavGroup[] = [
  {
    label: 'Overview',
    items: [{ label: 'Risk Overview', to: '/', icon: LayoutDashboard }],
  },
  {
    label: 'Assessment',
    items: [
      { label: 'Broker Summary', report: 'summary', icon: FileText },
      { label: 'Executive Summary', report: 'assessment', icon: Presentation },
      { label: 'Technical Report', report: 'full', icon: FileCode2 },
    ],
  },
  {
    label: 'Analytics',
    items: [
      { label: 'Risk Engine', to: '/risk-engine', icon: Gauge },
      { label: 'Financial Exposure', to: '/financial', icon: Coins },
      { label: 'Attack Surface', to: '/network', icon: Radar },
      { label: 'Vulnerabilities', to: '/vulnerabilities', icon: Bug },
      { label: 'Insurance Analytics', to: '/insurance', icon: ShieldCheck },
    ],
  },
  {
    label: 'Compliance',
    items: [
      { label: 'Framework Mapping', to: '/compliance', icon: ClipboardCheck },
      { label: 'Policies', to: '/technology', icon: ScrollText },
      { label: 'Regulatory Flags', to: '/regulatory', icon: Flag },
    ],
  },
  {
    label: 'Operations',
    items: [
      { label: 'Remediation', to: '/remediation', icon: Wrench },
      { label: 'Scan History', to: '/scan-history', icon: History },
      { label: 'Integrations', to: '/integrations', icon: Plug, disabled: true },
      { label: 'Settings', to: '/settings', icon: Settings, disabled: true },
    ],
  },
]

/** Secondary category tab bar on the overview / detail pages (spec §17). */
export interface CategoryTab { label: string; to: string; icon: LucideIcon }
export const CATEGORY_TABS: CategoryTab[] = [
  { label: 'Overview', to: '/', icon: LayoutDashboard },
  { label: 'Core Security', to: '/core-security', icon: Lock },
  { label: 'Email', to: '/email', icon: Mail },
  { label: 'Network', to: '/network', icon: Network },
  { label: 'Exposure', to: '/exposure', icon: Eye },
  { label: 'Technology', to: '/technology', icon: Cpu },
  { label: 'Compliance', to: '/compliance', icon: ClipboardCheck },
  { label: 'Discovery', to: '/discovery', icon: Search },
  { label: 'Insurance', to: '/insurance', icon: ShieldCheck },
  { label: 'Remediation', to: '/remediation', icon: Wrench },
]
