import { render } from '@testing-library/react'
import { MemoryRouter, Routes, Route } from 'react-router-dom'
import { ThemeProvider } from '../theme'

/** Mount a page the way the app mounts it: inside the router and the theme. */
export function renderPage(ui, { path = '/', route = '*' } = {}) {
  return render(
    <ThemeProvider>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={route} element={ui} />
        </Routes>
      </MemoryRouter>
    </ThemeProvider>
  )
}
