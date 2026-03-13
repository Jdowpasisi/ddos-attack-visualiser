import AttackGlobe from './components/AttackGlobe'
import { DashboardProvider } from './context/DashboardContext'

function App() {
  return (
    <DashboardProvider>
      <AttackGlobe />
    </DashboardProvider>
  )
}

export default App
