import type { LucideIcon } from 'lucide-react'
import {
  LayoutDashboard,
  ScanLine,
  ClipboardCheck,
  ShieldCheck,
  Boxes,
  RefreshCw,
  GitCompare,
  FileBarChart,
  ScrollText,
  Cpu,
  FileCog,
  Users,
  Radar,
  KeyRound,
  UserCog,
} from 'lucide-react'

export type NavGroup = 'operations' | 'governance' | 'admin'

export interface NavItem {
  to: string
  labelKey: string
  icon: LucideIcon
  group: NavGroup
  roles?: string[]
}

export const NAV_GROUP_ORDER: NavGroup[] = ['operations', 'governance', 'admin']

export const NAV_GROUP_LABEL_KEY: Record<NavGroup, string> = {
  operations: 'navGroup.operations',
  governance: 'navGroup.governance',
  admin: 'navGroup.admin',
}

export const NAV_ITEMS: NavItem[] = [
  { to: '/', labelKey: 'nav.dashboard', icon: LayoutDashboard, group: 'operations' },
  { to: '/scans', labelKey: 'nav.scans', icon: ScanLine, group: 'operations' },
  { to: '/reviews', labelKey: 'nav.reviews', icon: ClipboardCheck, group: 'operations', roles: ['approver', 'admin'] },
  {
    to: '/inventory',
    labelKey: 'nav.inventory',
    icon: Boxes,
    group: 'operations',
    roles: ['approver', 'auditor', 'admin'],
  },
  { to: '/reeval', labelKey: 'nav.reeval', icon: RefreshCw, group: 'operations', roles: ['approver', 'admin'] },
  { to: '/allowlist', labelKey: 'nav.allowlist', icon: ShieldCheck, group: 'governance', roles: ['approver', 'admin'] },
  {
    to: '/reconciliation',
    labelKey: 'nav.reconciliation',
    icon: GitCompare,
    group: 'governance',
    roles: ['admin', 'auditor'],
  },
  {
    to: '/reports',
    labelKey: 'nav.reports',
    icon: FileBarChart,
    group: 'governance',
    roles: ['approver', 'auditor', 'admin'],
  },
  { to: '/audit', labelKey: 'nav.audit', icon: ScrollText, group: 'governance', roles: ['auditor', 'admin'] },
  { to: '/admin/engines', labelKey: 'nav.adminEngines', icon: Cpu, group: 'admin', roles: ['admin'] },
  { to: '/admin/policy', labelKey: 'nav.adminPolicy', icon: FileCog, group: 'admin', roles: ['admin'] },
  { to: '/admin/users', labelKey: 'nav.adminUsers', icon: Users, group: 'admin', roles: ['admin'] },
  { to: '/admin/intel', labelKey: 'nav.adminIntel', icon: Radar, group: 'admin', roles: ['admin'] },
  {
    to: '/admin/ownership',
    labelKey: 'nav.adminOwnership',
    icon: UserCog,
    group: 'admin',
    roles: ['admin'],
  },
  { to: '/admin/breakglass', labelKey: 'nav.adminBreakglass', icon: KeyRound, group: 'admin', roles: ['admin'] },
]
