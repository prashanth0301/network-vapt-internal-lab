import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getAssessmentSummary } from '../services/assessmentService';
import { getCVEStatistics } from '../services/cveService';
import { getReports } from '../services/reportService';
import type { AssessmentSummary } from '../types/assessment';
import type { Report } from '../services/reportService';
import { AssessmentOverview } from './AssessmentOverview';

vi.mock('../services/assessmentService');
vi.mock('../services/cveService');
vi.mock('../services/reportService');
vi.mock('../hooks/useToast', () => ({
  useToast: () => ({ addToast: vi.fn() }),
}));

const mockedGetAssessmentSummary = vi.mocked(getAssessmentSummary);
const mockedGetCVEStatistics = vi.mocked(getCVEStatistics);
const mockedGetReports = vi.mocked(getReports);

function makeSummary(overrides: Partial<AssessmentSummary> = {}): AssessmentSummary {
  return {
    id: '1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d',
    name: 'Internal Lab Assessment',
    scan_type: 'full_assessment',
    target: '192.168.188.130',
    status: 'completed',
    parameters: {},
    created_at: '2026-08-04T00:00:00Z',
    updated_at: '2026-08-04T01:00:00Z',
    started_at: '2026-08-04T00:01:00Z',
    completed_at: '2026-08-04T01:45:00Z',
    error_message: null,
    duration_seconds: 6332,
    progress_percent: 100,
    progress: null,
    pipeline: null,
    severity_counts: { Critical: 51, High: 151, Medium: 185, Low: 18, Info: 6 },
    total_vulnerabilities: 411,
    hosts_count: 1,
    ports_count: 31,
    services_count: 31,
    reports_count: 3,
    exploits_count: 218,
    captures_count: 0,
    ...overrides,
  };
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/history/1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d']}>
      <Routes>
        <Route path="/history/:assessmentId" element={<AssessmentOverview />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('AssessmentOverview', () => {
  beforeEach(() => {
    mockedGetAssessmentSummary.mockReset();
    mockedGetCVEStatistics.mockReset();
    mockedGetReports.mockReset();
    mockedGetAssessmentSummary.mockResolvedValue({ data: makeSummary(), status: 'success' });
    mockedGetCVEStatistics.mockResolvedValue({
      data: { total_cves: 112, severity_counts: {}, kev_count: 0, exploit_count: 0, average_cvss: 0, average_epss: 0, top_vendors: [] },
      status: 'success',
    });
    mockedGetReports.mockResolvedValue([] as unknown as Report[]);
  });

  it('loads and renders all overview fields', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText('Internal Lab Assessment')).toBeTruthy());

    expect(screen.getByText('completed')).toBeTruthy();
    expect(screen.getByText(/^192\.168\.188\.130/)).toBeTruthy();
    expect(screen.getByText(/Full Assessment/)).toBeTruthy();
    expect(screen.getByText(/1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d/)).toBeTruthy();

    expect(screen.getByText('Risk Score')).toBeTruthy();
    expect(screen.getByText('Start Time')).toBeTruthy();
    expect(screen.getByText('End Time')).toBeTruthy();
    expect(screen.getByText('Duration')).toBeTruthy();
    expect(screen.getAllByText('Progress').length).toBeGreaterThan(0);

    expect(screen.getByText('Hosts')).toBeTruthy();
    expect(screen.getByText('Open Ports')).toBeTruthy();
    expect(screen.getByText('Services')).toBeTruthy();
    expect(screen.getByText('Vulnerabilities')).toBeTruthy();
    expect(screen.getByText('CVEs')).toBeTruthy();
    expect(screen.getByText('Exploits')).toBeTruthy();
    expect(screen.getByText('Reports')).toBeTruthy();

    expect(mockedGetAssessmentSummary).toHaveBeenCalledWith('1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d');
    expect(mockedGetCVEStatistics).toHaveBeenCalledWith('1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d');
    expect(mockedGetReports).toHaveBeenCalledWith({ assessmentId: '1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d' });
  });

  it('shows risk score and severity summary computed from counts', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText('Critical')).toBeTruthy());
    expect(screen.getByText('Risk Level')).toBeTruthy();
    expect(screen.getByText('Critical', { selector: 'span' })).toBeTruthy();
    expect(screen.getByText('51 (12%)')).toBeTruthy();
    expect(screen.getByText('151 (37%)')).toBeTruthy();
  });

  it('shows generated reports when present', async () => {
    const reports = [
      {
        id: 'rep-1',
        title: 'Executive Report',
        type: 'executive',
        format: 'PDF',
        size: '12.3 MB',
        date: '2026-08-04T02:00:00Z',
        status: 'completed',
        filepath: '/reports/rep-1.pdf',
        assessment_id: '1bab05f3-25bb-4bcf-9e66-7b0c0afb1c1d',
      } as Report,
    ];
    mockedGetReports.mockResolvedValue(reports);
    renderPage();
    await waitFor(() => expect(screen.getByText('Executive Report')).toBeTruthy());
    expect(screen.getByText('Generated Reports')).toBeTruthy();
    expect(screen.getAllByText('Download').length).toBe(1);
  });

  it('shows error state when summary load fails', async () => {
    mockedGetAssessmentSummary.mockRejectedValue(new Error('Not found'));
    renderPage();
    await waitFor(() => expect(screen.getByText(/Failed to load assessment/)).toBeTruthy());
    expect(screen.getByText(/Not found/)).toBeTruthy();
  });
});
