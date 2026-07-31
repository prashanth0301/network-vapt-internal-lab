import { useEffect, useState } from 'react';

const ID_KEY = 'vapt-active-assessment-id';
const NAME_KEY = 'vapt-active-assessment-name';
const CHANGE_EVENT = 'vapt-assessment-changed';

export function getActiveAssessmentId(): string | null {
  return localStorage.getItem(ID_KEY);
}

export function getActiveAssessmentName(): string | null {
  return localStorage.getItem(NAME_KEY);
}

export function setActiveAssessment(id: string, name?: string): void {
  localStorage.setItem(ID_KEY, id);
  if (name) localStorage.setItem(NAME_KEY, name);
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT));
}

export function clearActiveAssessment(): void {
  localStorage.removeItem(ID_KEY);
  localStorage.removeItem(NAME_KEY);
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT));
}

export function useAssessmentChangeTick(): number {
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const handler = () => setTick((t) => t + 1);
    window.addEventListener(CHANGE_EVENT, handler);
    return () => window.removeEventListener(CHANGE_EVENT, handler);
  }, []);
  return tick;
}
