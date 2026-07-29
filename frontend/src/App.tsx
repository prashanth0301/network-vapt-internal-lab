import { RouterProvider } from 'react-router-dom';

import { ThemeProvider } from './context/ThemeContext';
import { ToastProvider } from './context/ToastContext';
import { router } from './router';

export function App() {
  return (
    <ThemeProvider>
      <ToastProvider>
        <RouterProvider router={router} />
      </ToastProvider>
    </ThemeProvider>
  );
}
