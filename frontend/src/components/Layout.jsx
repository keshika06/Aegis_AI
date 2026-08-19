import Sidebar from './Sidebar'
import Topbar from './Topbar'

export default function Layout({ children }) {
  return (
    <div className="flex min-h-screen bg-base-bg text-slate-200">
      <Sidebar />
      <div className="flex-1 min-w-0">
        <Topbar />
        <main className="p-6 max-w-[1400px] mx-auto">{children}</main>
      </div>
    </div>
  )
}
