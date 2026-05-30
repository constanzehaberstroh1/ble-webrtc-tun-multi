import React, { useState, useEffect, useCallback } from 'react';
import { Card, Table, Button, Modal, Form, Select, Tag, Space, Typography, Popconfirm, message, Alert, Tooltip } from 'antd';
import { LinkOutlined, ThunderboltOutlined, PlusOutlined, DeleteOutlined, SyncOutlined, UserOutlined, CloudUploadOutlined } from '@ant-design/icons';
import { api } from '../../api';

const { Title, Text } = Typography;

export function PairingsPage() {
  const [pairings, setPairings] = useState<any[]>([]);
  const [accounts, setAccounts] = useState<any[]>([]);
  const [availableServers, setAvailableServers] = useState<any[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [panelRole, setPanelRole] = useState<string>('');
  const [clientID, setClientID] = useState<string>('');
  const [form] = Form.useForm();

  // Load client ID on mount
  useEffect(() => {
    api.getClientID().then(r => {
      setClientID(r.client_id || '');
    }).catch(() => {});
  }, []);

  const load = useCallback(async () => {
    try {
      const [p, a] = await Promise.all([
        api.listPairings(clientID || undefined),
        api.listAccounts()
      ]);
      setPairings(p);
      setAccounts(a);
    } catch (e: any) {
      message.error('Failed to load pairings');
    }
  }, [clientID]);

  // Load available servers when opening the create modal
  const loadAvailableServers = useCallback(async () => {
    try {
      const servers = await api.availableServers(clientID || undefined);
      setAvailableServers(servers);
    } catch {
      // Fallback to all servers
      const all = await api.listAccounts('SERVER');
      setAvailableServers(all);
    }
  }, [clientID]);

  // Detect panel role
  useEffect(() => {
    api.syncStatus().then(s => {
      setPanelRole(s.role === 'client' ? 'CLIENT' : 'SERVER');
    }).catch(() => {});
  }, []);

  // Load pairings: on CLIENT panels wait for clientID, on SERVER panels load all immediately
  useEffect(() => {
    if (panelRole === 'SERVER' || clientID !== '') {
      load();
    }
  }, [load, clientID, panelRole]);

  const handleAdd = async (values: any) => {
    setLoading(true);
    try {
      await api.createPairing(Number(values.clientId), Number(values.serverId), clientID);
      message.success('Pairing created successfully');
      setShowAdd(false);
      form.resetFields();
      load();
    } catch (e: any) {
      message.error(e.message || 'Failed to create pairing');
    } finally {
      setLoading(false);
    }
  };

  const autoPair = async () => {
    try {
      const r = await api.autoPair(clientID);
      message.success(`Auto-paired ${r.paired} accounts`);
      load();
    } catch (e: any) {
      message.error(e.message || 'Auto-pair failed');
    }
  };

  const remove = async (id: number) => {
    try {
      await api.deletePairing(id);
      message.success('Pairing deleted');
      load();
    } catch (e: any) {
      message.error('Failed to delete pairing');
    }
  };

  const pushToServer = async (id: number) => {
    try {
      await api.remotePushSinglePairing(id);
      message.success('Pairing pushed to remote server');
    } catch (e: any) {
      message.error(e.message || 'Failed to push pairing to server');
    }
  };

  const openAddModal = () => {
    loadAvailableServers();
    setShowAdd(true);
  };

  const timeAgo = (ts: string) => {
    if (!ts) return '—';
    const d = Date.now() - new Date(ts).getTime();
    if (d < 60000) return 'just now';
    if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
    if (d < 86400000) return Math.floor(d / 3600000) + 'h ago';
    return Math.floor(d / 86400000) + 'd ago';
  };

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      render: (text: string) => <Text strong>{text}</Text>,
    },
    {
      title: 'Client',
      key: 'client',
      render: (_: any, r: any) => (
        <Space>
          <Tag color="purple">CLIENT</Tag>
          {r.client_account?.provider_type && (
            <Tag color={r.client_account.provider_type === 'soroush' ? 'orange' : 'green'} style={{ fontSize: 10, fontWeight: 'bold' }}>
              {r.client_account.provider_type.toUpperCase()}
            </Tag>
          )}
          <Text type="secondary" className="font-mono">
            {r.client_account?.external_id || r.client_account?.bale_user_id || r.client_account_id}
          </Text>
          {r.client_account?.display_name && (
            <Text type="secondary" style={{ fontSize: 11 }}>({r.client_account.display_name})</Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Server',
      key: 'server',
      render: (_: any, r: any) => (
        <Space>
          <Tag color="blue">SERVER</Tag>
          {r.server_account?.provider_type && (
            <Tag color={r.server_account.provider_type === 'soroush' ? 'orange' : 'green'} style={{ fontSize: 10, fontWeight: 'bold' }}>
              {r.server_account.provider_type.toUpperCase()}
            </Tag>
          )}
          <Text type="secondary" className="font-mono">
            {r.server_account?.external_id || r.server_account?.bale_user_id || r.server_account_id}
          </Text>
          {r.server_account?.display_name && (
            <Text type="secondary" style={{ fontSize: 11 }}>({r.server_account.display_name})</Text>
          )}
        </Space>
      ),
    },
    {
      title: 'Status',
      key: 'status',
      render: (_: any, r: any) => (
        r.active ? <Tag color="success">Active</Tag> : <Tag color="default">Inactive</Tag>
      ),
    },
    {
      title: 'Created',
      dataIndex: 'created_at',
      key: 'created_at',
      render: (ts: string) => timeAgo(ts),
    },
    {
      title: 'Action',
      key: 'action',
      render: (_: any, r: any) => (
        <Space>
          <Button size="small" icon={<CloudUploadOutlined />} onClick={() => pushToServer(r.id)}
            style={{ color: '#52c41a', borderColor: '#52c41a' }}>
            Push
          </Button>
          <Popconfirm
            title="Delete the pairing"
            description="Are you sure to delete this pairing?"
            onConfirm={() => remove(r.id)}
            okText="Yes"
            cancelText="No"
          >
            <Button size="small" danger icon={<DeleteOutlined />}>Delete</Button>
          </Popconfirm>
        </Space>
      ),
    },
  ];

  const clients = accounts.filter((a: any) => a.role === 'CLIENT');

  // Already-paired server IDs by THIS client — allowed in dropdown too (for reference)
  const pairedServerIDs = new Set(pairings.map((p: any) => p.server_account_id));

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-end mb-8">
        <div>
          <Title level={2} style={{ margin: 0 }}>Pairings</Title>
          <Text type="secondary">
            Client ↔ Server account mappings
            {panelRole && <Tag color={panelRole === 'CLIENT' ? 'purple' : 'blue'} style={{ marginLeft: 8 }}>{panelRole} Panel</Tag>}
            {clientID && (
              <Tooltip title="Your unique client ID — other clients cannot use your paired servers">
                <Tag icon={<UserOutlined />} color="geekblue" style={{ marginLeft: 4 }}>{clientID.slice(0, 8)}…</Tag>
              </Tooltip>
            )}
          </Text>
        </div>
        <Space>
          <Button icon={<ThunderboltOutlined />} onClick={autoPair}>
            Auto-Pair
          </Button>
          <Button type="primary" icon={<PlusOutlined />} onClick={openAddModal}>
            Create Pairing
          </Button>
        </Space>
      </div>

      <Alert
        message="Multi-user pairing system"
        description="Each client has a unique identity. Server accounts paired by you cannot be used by other clients. Available servers in the dropdown exclude those already paired by others."
        type="info"
        showIcon
        icon={<SyncOutlined />}
        className="mb-4"
      />

      <Card bordered={false} className="shadow-sm">
        <Table
          dataSource={pairings}
          columns={columns}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          locale={{
            emptyText: (
              <div className="py-8">
                <LinkOutlined className="text-4xl text-slate-300 mb-2" />
                <p>No pairings yet</p>
              </div>
            )
          }}
        />
      </Card>

      <Modal
        title="Create Pairing"
        open={showAdd}
        onCancel={() => {
          setShowAdd(false);
          form.resetFields();
        }}
        footer={null}
      >
        <Form
          form={form}
          layout="vertical"
          onFinish={handleAdd}
          className="mt-4"
        >
          <Form.Item name="clientId" label="Client Account" rules={[{ required: true, message: 'Please select a client account' }]}>
            <Select placeholder="Select client...">
              {clients.map((c: any) => (
                <Select.Option key={c.id} value={c.id}>
                  #{c.id} — [{(c.provider_type || 'bale').toUpperCase()}] {c.external_id || c.bale_user_id} {c.display_name ? `(${c.display_name})` : ''}
                </Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item name="serverId" label="Server Account (available only)" rules={[{ required: true, message: 'Please select a server account' }]}>
            <Select placeholder="Select server...">
              {availableServers.map((s: any) => (
                <Select.Option key={s.id} value={s.id}>
                  #{s.id} — [{(s.provider_type || 'bale').toUpperCase()}] {s.external_id || s.bale_user_id} {s.display_name ? `(${s.display_name})` : ''}
                  {pairedServerIDs.has(s.id) ? ' ✓ (your pairing)' : ''}
                </Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item className="mb-0 flex justify-end">
            <Space>
              <Button onClick={() => setShowAdd(false)}>Cancel</Button>
              <Button type="primary" htmlType="submit" loading={loading}>
                Create
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
}
