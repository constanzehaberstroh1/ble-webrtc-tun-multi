import React, { useState, useEffect, useCallback } from 'react';
import { Card, Table, Typography, Tag, Space, Row, Col, Statistic, Select, Button, Popconfirm, message } from 'antd';
import { HistoryOutlined, CloudUploadOutlined, CloudDownloadOutlined, ClockCircleOutlined, ThunderboltOutlined, StopOutlined, DisconnectOutlined } from '@ant-design/icons';
import { api } from '../../api';

const { Title, Text } = Typography;

export function ConnectionsPage() {
  const [history, setHistory] = useState<any[]>([]);
  const [accounts, setAccounts] = useState<any[]>([]);
  const [filterAccount, setFilterAccount] = useState<number | null>(null);
  const [endingCall, setEndingCall] = useState<number | null>(null);
  const [endingAll, setEndingAll] = useState(false);

  const load = useCallback(async () => {
    try {
      const [h, a] = await Promise.all([
        api.getHistory(100),
        api.listAccounts(),
      ]);
      setHistory(Array.isArray(h) ? h : []);
      setAccounts(a || []);
    } catch (e) {
      console.error(e);
    }
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 10000);
    return () => clearInterval(interval);
  }, [load]);

  const timeAgo = (ts: string) => {
    if (!ts) return '—';
    const d = Date.now() - new Date(ts).getTime();
    if (d < 60000) return 'just now';
    if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
    if (d < 86400000) return Math.floor(d / 3600000) + 'h ago';
    return Math.floor(d / 86400000) + 'd ago';
  };

  const fmt = (b: number) => {
    if (!b) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB'];
    let i = 0, v = b;
    while (v >= 1024 && i < 3) { v /= 1024; i++; }
    return v.toFixed(i > 0 ? 1 : 0) + ' ' + u[i];
  };

  const durationStr = (start: string, end: string) => {
    if (!start) return '—';
    const s = new Date(start).getTime();
    const e = end ? new Date(end).getTime() : Date.now();
    const sec = Math.round((e - s) / 1000);
    if (sec < 60) return sec + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm ' + (sec % 60) + 's';
    return Math.floor(sec / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
  };

  // Filter history by account
  const filteredHistory = filterAccount
    ? history.filter((h: any) => h.server_account_id === filterAccount || h.client_account_id === filterAccount)
    : history;

  // Aggregate stats
  const totalSent = filteredHistory.reduce((sum: number, h: any) => sum + (h.bytes_sent || 0), 0);
  const totalRecv = filteredHistory.reduce((sum: number, h: any) => sum + (h.bytes_received || 0), 0);
  const totalSessions = filteredHistory.length;
  const activeSessions = filteredHistory.filter((h: any) => !h.end_time).length;

  // Per-account traffic summary
  const accountTraffic = accounts.map((a: any) => {
    const sessions = history.filter((h: any) => h.server_account_id === a.id || h.client_account_id === a.id);
    const sent = sessions.reduce((s: number, h: any) => s + (h.bytes_sent || 0), 0);
    const recv = sessions.reduce((s: number, h: any) => s + (h.bytes_received || 0), 0);
    return { ...a, sessionCount: sessions.length, totalSent: sent, totalReceived: recv };
  }).filter((a: any) => a.sessionCount > 0);

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      width: 60,
      render: (text: string) => <Text strong>{text}</Text>,
    },
    {
      title: 'Account',
      key: 'account',
      render: (_: any, r: any) => (
        <Space>
          {r.server_account_id && <Tag color="blue">Server #{r.server_account_id}</Tag>}
          {r.client_account_id && <Tag color="purple">Client #{r.client_account_id}</Tag>}
        </Space>
      ),
    },
    {
      title: 'Call ID',
      dataIndex: 'call_id',
      key: 'call_id',
      render: (text: string) => <Tag color="purple" className="font-mono">{text || '—'}</Tag>,
    },
    {
      title: 'Room',
      dataIndex: 'room_id',
      key: 'room_id',
      render: (text: string) => <Text type="secondary" style={{ fontSize: 11 }}>{text || '—'}</Text>,
    },
    {
      title: 'Started',
      dataIndex: 'start_time',
      key: 'start_time',
      render: (ts: string) => timeAgo(ts),
    },
    {
      title: 'Duration',
      key: 'duration',
      render: (_: any, r: any) => {
        if (!r.end_time) return <Tag color="green">LIVE</Tag>;
        return <Text>{durationStr(r.start_time, r.end_time)}</Text>;
      },
    },
    {
      title: 'Sent',
      dataIndex: 'bytes_sent',
      key: 'bytes_sent',
      render: (b: number) => <Text type="success" className="font-mono text-xs">{fmt(b)}</Text>,
    },
    {
      title: 'Received',
      dataIndex: 'bytes_received',
      key: 'bytes_received',
      render: (b: number) => <Text className="font-mono text-xs" style={{ color: '#06b6d4' }}>{fmt(b)}</Text>,
    },
    {
      title: 'Status',
      key: 'status',
      render: (_: any, r: any) => {
        if (!r.termination) return <Tag color="success">Active</Tag>;
        const color = r.termination === 'ERROR' ? 'error' : r.termination === 'TIMEOUT' ? 'default' : 'warning';
        return <Tag color={color}>{r.termination}</Tag>;
      },
    },
    {
      title: 'Action',
      key: 'action',
      width: 100,
      render: (_: any, r: any) => {
        if (r.end_time) return null; // Already ended
        return (
          <Popconfirm
            title="End this call?"
            description="This will force-disconnect the active tunnel session."
            onConfirm={async () => {
              setEndingCall(r.server_account_id);
              try {
                await api.forceEndCall(r.server_account_id);
                message.success('Call ended');
                load();
              } catch (e: any) {
                message.error(e.message || 'Failed to end call');
              } finally {
                setEndingCall(null);
              }
            }}
            okText="End Call"
            okButtonProps={{ danger: true }}
          >
            <Button
              danger
              size="small"
              icon={<StopOutlined />}
              loading={endingCall === r.server_account_id}
            >
              End
            </Button>
          </Popconfirm>
        );
      },
    },
  ];

  const accountTrafficCols = [
    { title: 'Account', key: 'account', render: (_: any, r: any) => <Space><Tag color={r.role === 'SERVER' ? 'blue' : 'purple'}>{r.role}</Tag>{r.provider_type && <Tag color={r.provider_type === 'soroush' ? 'orange' : 'green'} style={{ fontSize: 10, fontWeight: 'bold' }}>{r.provider_type.toUpperCase()}</Tag>}<Text strong>#{r.id}</Text><Text type="secondary">{r.display_name || r.external_id || r.bale_user_id}</Text></Space> },
    { title: 'Sessions', dataIndex: 'sessionCount', key: 'sessions' },
    { title: 'Sent', key: 'sent', render: (_: any, r: any) => <Text type="success" className="font-mono">{fmt(r.totalSent)}</Text> },
    { title: 'Received', key: 'recv', render: (_: any, r: any) => <Text className="font-mono" style={{ color: '#06b6d4' }}>{fmt(r.totalReceived)}</Text> },
    { title: 'Total', key: 'total', render: (_: any, r: any) => <Text strong className="font-mono">{fmt(r.totalSent + r.totalReceived)}</Text> },
  ];

  return (
    <div className="space-y-6">
      <div className="mb-8 flex justify-between items-end">
        <div>
          <Title level={2} style={{ margin: 0 }}>Connection History</Title>
          <Text type="secondary">Session history &amp; per-account traffic stats</Text>
        </div>
        <Space>
          {activeSessions > 0 && (
            <Popconfirm
              title={`End all ${activeSessions} active call(s)?`}
              description="This will force-disconnect ALL active tunnel sessions."
              onConfirm={async () => {
                setEndingAll(true);
                try {
                  const res = await api.forceEndAllCalls();
                  message.success(res.message || 'All calls ended');
                  load();
                } catch (e: any) {
                  message.error(e.message || 'Failed');
                } finally {
                  setEndingAll(false);
                }
              }}
              okText="End All"
              okButtonProps={{ danger: true }}
            >
              <Button danger type="primary" icon={<DisconnectOutlined />} loading={endingAll}>
                End All Calls ({activeSessions})
              </Button>
            </Popconfirm>
          )}
          <Select
            allowClear
            placeholder="Filter by account"
            style={{ width: 200 }}
            onChange={(v: number) => setFilterAccount(v || null)}
            value={filterAccount}
          >
            {accounts.map((a: any) => (
              <Select.Option key={a.id} value={a.id}>
                #{a.id} — [{(a.provider_type || 'bale').toUpperCase()}] {a.display_name || a.external_id || a.bale_user_id} ({a.role})
              </Select.Option>
            ))}
          </Select>
        </Space>
      </div>

      <Row gutter={[16, 16]}>
        <Col xs={12} sm={6}>
          <Card bordered={false} className="shadow-sm">
            <Statistic title="Total Sessions" value={totalSessions} prefix={<ThunderboltOutlined className="text-purple-500 mr-1" />} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card bordered={false} className="shadow-sm">
            <Statistic title="Active Now" value={activeSessions} prefix={<ClockCircleOutlined className="text-green-500 mr-1" />} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card bordered={false} className="shadow-sm">
            <Statistic title="Total Sent" value={fmt(totalSent)} prefix={<CloudUploadOutlined className="text-indigo-500 mr-1" />} />
          </Card>
        </Col>
        <Col xs={12} sm={6}>
          <Card bordered={false} className="shadow-sm">
            <Statistic title="Total Received" value={fmt(totalRecv)} prefix={<CloudDownloadOutlined className="text-sky-500 mr-1" />} />
          </Card>
        </Col>
      </Row>

      {/* Per-Account Traffic */}
      {accountTraffic.length > 0 && (
        <Card title="Per-Account Traffic" bordered={false} className="shadow-sm">
          <Table
            dataSource={accountTraffic}
            columns={accountTrafficCols}
            rowKey="id"
            pagination={false}
            size="small"
          />
        </Card>
      )}

      {/* Session History */}
      <Card bordered={false} className="shadow-sm">
        <Table
          dataSource={filteredHistory}
          columns={columns}
          rowKey="id"
          pagination={{ pageSize: 15, showSizeChanger: true, pageSizeOptions: ['10', '15', '25', '50'] }}
          locale={{
            emptyText: (
              <div className="py-8">
                <HistoryOutlined className="text-4xl text-slate-300 mb-2" />
                <p>No connection history yet</p>
              </div>
            )
          }}
        />
      </Card>
    </div>
  );
}
