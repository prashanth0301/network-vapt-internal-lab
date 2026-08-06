import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthContext } from '../context/AuthContext';
import * as captureService from '../services/captureService';
import type { PacketCapture, CapturePacket } from '../services/captureService';
import type { User } from '../types/auth';
import { Packets } from './Packets';

vi.mock('../services/captureService');
vi.mock('../services/assessmentStore', () => ({
  useAssessmentChangeTick: () => 0,
  getActiveAssessmentId: () => null,
  getActiveAssessmentName: () => null,
  getActiveAssessmentStatus: () => null,
}));
vi.mock('../hooks/useToast', () => ({
  useToast: () => ({ addToast: vi.fn() }),
}));

const mocked = vi.mocked(captureService);

const capture: PacketCapture = {
  id: '046aedb0-119d-4057-903a-ce8a385764a5',
  filename: 'live_046aedb0-119d-4057-903a-ce8a385764a5.pcap',
  size: '66.0 KB',
  packets: 526,
  duration: '10s',
  date: '2026-08-05T11:02:53.798812+00:00',
  status: 'completed',
  protocol_stats: { TCP: 526 },
  total_bytes: 59589,
  avg_packet_size: 113.3,
  packets_per_second: 48.38,
  scan_id: null,
  conversation_count: 4,
  started_at: '2026-08-05T11:02:53.797025+00:00',
  ended_at: '2026-08-05T11:03:02.201986+00:00',
};

const packets: CapturePacket[] = [
  {
    id: '9d076697-39f2-462c-b7d0-e10bddb9359d',
    seq: 0,
    timestamp: '2026-08-05T11:02:51.329969+00:00',
    src_ip: '172.18.0.4',
    dst_ip: '172.18.0.3',
    src_port: 44638,
    dst_port: 5432,
    protocol: 'TCP',
    length: 66,
    info: '44638 \u2192 5432 [ACK]',
  },
  {
    id: 'a242e9cc-3f6b-4925-a104-89a5f2144754',
    seq: 1,
    timestamp: '2026-08-05T11:02:52.170048+00:00',
    src_ip: '172.18.0.1',
    dst_ip: '172.18.0.4',
    src_port: 45766,
    dst_port: 8000,
    protocol: 'TCP',
    length: 66,
    info: '45766 \u2192 8000 [ACK]',
  },
];

const user: User = {
  id: 'user-1',
  username: 'admin',
  email: 'admin@example.com',
  full_name: null,
  role: 'administrator',
  status: 'active',
  last_login: null,
  is_active: true,
  permissions: ['view:audit', 'manage:users'],
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

function renderPage() {
  return render(
    <MemoryRouter>
      <AuthContext.Provider
        value={{
          user,
          token: 'token',
          isAuthenticated: true,
          isLoading: false,
          loginToken: vi.fn(),
          logout: vi.fn(),
          hasPermission: () => true,
          hasRole: () => true,
        }}
      >
        <Packets />
      </AuthContext.Provider>
    </MemoryRouter>,
  );
}

describe('Packets page - completed capture packet list', () => {
  beforeEach(() => {
    mocked.getCaptures.mockResolvedValue([capture]);
    mocked.getCaptureProtocols.mockResolvedValue([]);
    mocked.getCaptureInterfaces.mockResolvedValue([]);
    mocked.getCapture.mockResolvedValue(capture);
    mocked.getCaptureConversations.mockResolvedValue([]);
    mocked.getCapturePackets.mockResolvedValue({
      items: packets,
      total: 526,
      page: 1,
      per_page: 50,
    });
    mocked.getCaptureStatus.mockResolvedValue(null);
  });

  it('renders packets in the table after selecting a completed capture', async () => {
    renderPage();

    await waitFor(() => expect(screen.getByText('live_046aedb0-119d-4057-903a-ce8a385764a5.pcap')).toBeTruthy());

    await fireEvent.click(screen.getByText('live_046aedb0-119d-4057-903a-ce8a385764a5.pcap'));

    await waitFor(() => expect(screen.getByText('172.18.0.4:44638')).toBeTruthy());
    expect(screen.getByText('172.18.0.3:5432')).toBeTruthy();
    expect(screen.getByText('45766 \u2192 8000 [ACK]')).toBeTruthy();
    expect(mocked.getCapturePackets).toHaveBeenCalledWith(
      '046aedb0-119d-4057-903a-ce8a385764a5',
      1,
      50,
      undefined,
    );
  });

  it('downloads the capture PCAP via the Download button', async () => {
    mocked.downloadCapture.mockResolvedValue(undefined);
    renderPage();

    await waitFor(() => expect(screen.getByText('live_046aedb0-119d-4057-903a-ce8a385764a5.pcap')).toBeTruthy());
    await fireEvent.click(screen.getByText('live_046aedb0-119d-4057-903a-ce8a385764a5.pcap'));

    await waitFor(() => expect(screen.getByText('Download PCAP')).toBeTruthy());
    await fireEvent.click(screen.getByText('Download PCAP'));

    await waitFor(() =>
      expect(mocked.downloadCapture).toHaveBeenCalledWith(
        '046aedb0-119d-4057-903a-ce8a385764a5',
        'live_046aedb0-119d-4057-903a-ce8a385764a5.pcap',
      ),
    );
  });

  it('passes search param to getCaptures when typing', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText('live_046aedb0-119d-4057-903a-ce8a385764a5.pcap')).toBeTruthy());

    const searchInput = screen.getByPlaceholderText('Search by filename, protocol, date...');
    fireEvent.change(searchInput, { target: { value: 'test' } });

    await waitFor(() =>
      expect(mocked.getCaptures).toHaveBeenCalledWith(undefined, 'test'),
    );
  });

  it('shows Delete button for admin users', async () => {
    renderPage();
    await waitFor(() => expect(screen.getByText('live_046aedb0-119d-4057-903a-ce8a385764a5.pcap')).toBeTruthy());
    expect(screen.getByText('Delete')).toBeTruthy();
  });

  it('calls deleteCapture and refreshes after confirmation', async () => {
    mocked.deleteCapture.mockResolvedValue({ message: 'Capture deleted' });
    renderPage();
    await waitFor(() => expect(screen.getByText('live_046aedb0-119d-4057-903a-ce8a385764a5.pcap')).toBeTruthy());

    const deleteButtons = screen.getAllByText('Delete');
    fireEvent.click(deleteButtons[0]);

    await waitFor(() => expect(screen.getByText('Delete Capture')).toBeTruthy());
    expect(screen.getByText(/permanently delete/)).toBeTruthy();

    const modalDeleteButtons = screen.getAllByText('Delete');
    fireEvent.click(modalDeleteButtons[modalDeleteButtons.length - 1]);

    await waitFor(() =>
      expect(mocked.deleteCapture).toHaveBeenCalledWith(
        '046aedb0-119d-4057-903a-ce8a385764a5',
      ),
    );
  });
});
