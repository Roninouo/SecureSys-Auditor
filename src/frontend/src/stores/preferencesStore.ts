import { create } from 'zustand'
import { persist } from 'zustand/middleware'

interface PreferencesState {
  showSyntheticData: boolean
  setShowSyntheticData: (value: boolean) => void
  toggleShowSyntheticData: () => void
}

export const usePreferencesStore = create<PreferencesState>()(
  persist(
    (set, get) => ({
      // Default to hiding synthetic data; real data is always included.
      showSyntheticData: false,

      setShowSyntheticData: (value) => set({ showSyntheticData: value }),

      toggleShowSyntheticData: () =>
        set({ showSyntheticData: !get().showSyntheticData }),
    }),
    {
      name: 'preferences-storage',
    }
  )
)
