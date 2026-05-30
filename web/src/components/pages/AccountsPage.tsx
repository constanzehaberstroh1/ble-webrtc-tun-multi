import React, { useState, useEffect, useCallback } from 'react';
import { Card, Table, Button, Modal, Form, Input, Tag, Space, Typography, Popconfirm, message, Steps, Alert, Radio } from 'antd';
import { PlusOutlined, DeleteOutlined, UserOutlined, MobileOutlined, SafetyOutlined, ProfileOutlined, CloudUploadOutlined, PhoneOutlined } from '@ant-design/icons';
import { api } from '../../api';
import { AccountDetailsDrawer } from '../organisms';

const { Title, Text } = Typography;
const { TextArea } = Input;

export function AccountsPage() {
  const [accounts, setAccounts] = useState<any[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [showOTP, setShowOTP] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedAccountId, setSelectedAccountId] = useState<number | null>(null);
  const [panelRole, setPanelRole] = useState<string>(''); // auto-detected
  const [endingCall, setEndingCall] = useState<number | null>(null);
  const [form] = Form.useForm();

  // OTP state
  const [otpStep, setOtpStep] = useState(0); // 0 = phone, 1 = code
  const [otpPhone, setOtpPhone] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [otpLoading, setOtpLoading] = useState(false);
  const [otpMessage, setOtpMessage] = useState('');
  const [providerVal, setProviderVal] = useState<'bale' | 'soroush'>('bale');

  const load = useCallback(async () => {
    try {
      setAccounts(await api.listAccounts());
    } catch (e: any) {
      message.error('Failed to load accounts');
    }
  }, []);

  // Auto-detect panel role from sync status
  useEffect(() => {
    api.syncStatus().then(s => {
      const role = s.role === 'client' ? 'CLIENT' : 'SERVER';
      setPanelRole(role);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const handleAdd = async (values: any) => {
    setLoading(true);
    try {
      // Role is auto-determined by the backend — no need to specify
      await api.createAccount(values.token);
      message.success('Account added successfully');
      setShowAdd(false);
      form.resetFields();
      load();
    } catch (e: any) {
      message.error(e.message || 'Failed to add account');
    } finally {
      setLoading(false);
    }
  };

  const toggle = async (id: number, enabled: boolean) => {
    try {
      await api.updateAccount(id, { enabled: !enabled });
      message.success(`Account ${!enabled ? 'enabled' : 'disabled'}`);
      load();
    } catch (e: any) {
      message.error('Failed to update account status');
    }
  };

  const remove = async (id: number) => {
    try {
      await api.deleteAccount(id);
      message.success('Account deleted');
      load();
    } catch (e: any) {
      message.error('Failed to delete account');
    }
  };

  const handleSyncAll = async () => {
    try {
      // Sync locally
      await api.syncAllAccounts();
      // Also sync remote server (Clever Cloud)
      try {
        await api.remoteSyncAll();
        message.success('Sync started on both local and remote server');
      } catch (remoteErr: any) {
        message.warning('Local sync started, but remote server sync failed: ' + (remoteErr.message || 'unknown'));
      }
    } catch (e: any) {
      message.error('Failed to start sync');
    }
  };

  const pushToServer = async (id: number) => {
    try {
      await api.remotePushSingleAccount(id);
      message.success('Account pushed to remote server');
    } catch (e: any) {
      message.error(e.message || 'Failed to push account to server');
    }
  };

  const pullFromServer = async () => {
    try {
      const result = await api.remotePullAccounts();
      if (result.inserted > 0) {
        message.success(`Pulled ${result.inserted} new server account(s) from remote`);
        load();
      } else {
        message.info('No new server accounts to pull — all synced');
      }
    } catch (e: any) {
      message.error(e.message || 'Failed to pull accounts from server');
    }
  };

  // OTP handlers
  const handleOTPStart = async () => {
    if (!otpPhone || otpPhone.length < 10) {
      message.error('Please enter a valid phone number');
      return;
    }
    setOtpLoading(true);
    setOtpMessage('');
    try {
      const res = await api.baleLoginStart(otpPhone, providerVal);
      setOtpMessage(res.message || 'OTP sent!');
      setOtpStep(1);
      message.success('OTP code sent to ' + otpPhone);
    } catch (e: any) {
      message.error(e.message || 'Failed to send OTP');
    } finally {
      setOtpLoading(false);
    }
  };

  const handleOTPVerify = async () => {
    if (!otpCode || otpCode.length < 4) {
      message.error('Please enter the OTP code');
      return;
    }
    setOtpLoading(true);
    setOtpMessage('');
    try {
      // Role is auto-determined by backend — no need to specify
      const res = await api.baleLoginVerify(otpPhone, otpCode, providerVal);
      message.success(`Account ${res.updated ? 'updated' : 'created'}: ${res.phone || res.name || res.user_id}`);
      setShowOTP(false);
      resetOTP();
      load();
    } catch (e: any) {
      message.error(e.message || 'OTP verification failed');
      setOtpMessage(e.message || 'Verification failed. Try again.');
    } finally {
      setOtpLoading(false);
    }
  };

  const resetOTP = () => {
    setOtpStep(0);
    setOtpPhone('');
    setOtpCode('');
    setOtpMessage('');
    setProviderVal('bale');
  };

  const timeAgo = (ts: string) => {
    if (!ts) return '—';
    const d = Date.now() - new Date(ts).getTime();
    if (d < 60000) return 'just now';
    if (d < 3600000) return Math.floor(d / 60000) + 'm ago';
    if (d < 86400000) return Math.floor(d / 3600000) + 'h ago';
    return Math.floor(d / 86400000) + 'd ago';
  };

  const getRoleColor = (role: string) => {
    return role === 'SERVER' ? 'blue' : 'purple';
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'IDLE': return 'blue';
      case 'IN_CALL': return 'green';
      case 'RESERVED': return 'orange';
      case 'OFFLINE': return 'default';
      case 'ERROR': return 'red';
      default: return 'default';
    }
  };

  // Determine if this account is "local" (matches panel role) or "remote" (synced from other side)
  const isLocalAccount = (role: string) => role === panelRole;

  const columns = [
    {
      title: 'ID',
      dataIndex: 'id',
      key: 'id',
      render: (text: string) => <Text strong>{text}</Text>,
    },
    {
      title: 'Provider',
      dataIndex: 'provider_type',
      key: 'provider_type',
      render: (prov: string) => {
        const val = prov || 'bale';
        const color = val === 'soroush' ? 'orange' : 'green';
        return <Tag color={color} style={{ textTransform: 'uppercase', fontWeight: 'bold' }}>{val}</Tag>;
      },
    },
    {
      title: 'External ID',
      dataIndex: 'external_id',
      key: 'external_id',
      render: (text: string, r: any) => {
        const val = text || r.bale_user_id;
        return <Tag color="cyan" className="font-mono">{val}</Tag>;
      },
    },
    {
      title: 'Role',
      dataIndex: 'role',
      key: 'role',
      render: (role: string) => (
        <Space>
          <Tag color={getRoleColor(role)}>{role}</Tag>
          {!isLocalAccount(role) && <Tag color="orange" style={{ fontSize: '10px' }}>synced</Tag>}
        </Space>
      ),
    },
    {
      title: 'Status',
      dataIndex: 'status',
      key: 'status',
      render: (status: string) => <Tag color={getStatusColor(status)}>{status}</Tag>,
    },
    {
      title: 'Name',
      dataIndex: 'display_name',
      key: 'name',
      render: (text: string) => <Text type="secondary">{text || '—'}</Text>,
    },
    {
      title: 'Phone',
      dataIndex: 'phone',
      key: 'phone',
      render: (text: string) => <Text type="secondary">{text || '—'}</Text>,
    },
    {
      title: 'Last Seen',
      dataIndex: 'last_seen',
      key: 'last_seen',
      render: (ts: string) => timeAgo(ts),
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_: any, r: any) => (
        <Space wrap>
          {r.status === 'IN_CALL' && (
            <Popconfirm
              title="End this call?"
              description="Force-disconnect the active tunnel session."
              onConfirm={async () => {
                setEndingCall(r.id);
                try {
                  await api.forceEndCall(r.id);
                  message.success('Call ended for account #' + r.id);
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
              <Button size="small" danger type="primary" icon={<PhoneOutlined />} loading={endingCall === r.id}>
                End Call
              </Button>
            </Popconfirm>
          )}
          <Button size="small" type="primary" ghost icon={<ProfileOutlined />} onClick={() => setSelectedAccountId(r.id)}>
            Details
          </Button>
          <Button size="small" icon={<CloudUploadOutlined />} onClick={() => pushToServer(r.id)}
            style={{ color: '#52c41a', borderColor: '#52c41a' }}>
            Push
          </Button>
          {isLocalAccount(r.role) && (
            <>
              <Button size="small" onClick={() => toggle(r.id, r.enabled)} type={r.enabled ? 'default' : 'primary'}>
                {r.enabled ? 'Disable' : 'Enable'}
              </Button>
              <Popconfirm
                title="Delete the account"
                description="Are you sure to delete this account?"
                onConfirm={() => remove(r.id)}
                okText="Yes"
                cancelText="No"
              >
                <Button size="small" danger icon={<DeleteOutlined />} />
              </Popconfirm>
            </>
          )}
        </Space>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-end mb-8">
        <div>
          <Title level={2} style={{ margin: 0 }}>Accounts</Title>
          <Text type="secondary">
            Manage Bale token accounts
            {panelRole && <Tag color={panelRole === 'CLIENT' ? 'purple' : 'blue'} style={{ marginLeft: 8 }}>{panelRole} Panel</Tag>}
          </Text>
        </div>
        <Space wrap>
          <Button onClick={handleSyncAll}>Sync All</Button>
          <Button type="primary" icon={<MobileOutlined />} onClick={() => setShowOTP(true)}
            style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', border: 'none' }}>
            Login with OTP
          </Button>
          <Button icon={<PlusOutlined />} onClick={() => setShowAdd(true)}>
            Add by Token
          </Button>
        </Space>
      </div>

      {panelRole && (
        <Alert
          message={`${panelRole} Admin Panel`}
          description={`New accounts added here will automatically be assigned the ${panelRole} role. ${
            panelRole === 'CLIENT' 
              ? 'SERVER accounts are synced from the remote server automatically.'
              : 'CLIENT accounts are synced from the client admin panel automatically.'
          }`}
          type="info"
          showIcon
          className="mb-4"
        />
      )}

      <Card bordered={false} className="shadow-sm">
        <Table
          dataSource={accounts}
          columns={columns}
          rowKey="id"
          pagination={{ pageSize: 10 }}
          locale={{
            emptyText: (
              <div className="py-8">
                <UserOutlined className="text-4xl text-slate-300 mb-2" />
                <p>No accounts yet</p>
              </div>
            )
          }}
        />
      </Card>

      {/* OTP Login Modal — Role is auto-determined, no role selector */}
      <Modal
        title={
          <Space>
            <MobileOutlined style={{ color: '#667eea' }} />
            <span>Add Account via OTP</span>
            {panelRole && <Tag color={panelRole === 'CLIENT' ? 'purple' : 'blue'}>{panelRole}</Tag>}
          </Space>
        }
        open={showOTP}
        onCancel={() => { setShowOTP(false); resetOTP(); }}
        footer={null}
        width={480}
      >
        <Steps
          current={otpStep}
          size="small"
          className="mb-6 mt-4"
          items={[
            { title: 'Phone Number', icon: <MobileOutlined /> },
            { title: 'Verify Code', icon: <SafetyOutlined /> },
          ]}
        />

        {otpMessage && (
          <Alert
            message={otpMessage}
            type={otpStep === 1 ? 'success' : 'info'}
            showIcon
            className="mb-4"
          />
        )}

        {otpStep === 0 && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-1">Select Provider</label>
              <Radio.Group
                value={providerVal}
                onChange={e => setProviderVal(e.target.value)}
                className="mb-4 w-full flex"
                buttonStyle="solid"
              >
                <Radio.Button value="bale" className="flex-1 text-center" style={{ fontWeight: 'bold' }}>Bale</Radio.Button>
                <Radio.Button value="soroush" className="flex-1 text-center" style={{ fontWeight: 'bold' }}>Soroush</Radio.Button>
              </Radio.Group>
            </div>

            <div>
              <label className="block text-sm font-medium mb-1">Phone Number</label>
              <Input
                size="large"
                placeholder="09151016774"
                value={otpPhone}
                onChange={e => setOtpPhone(e.target.value)}
                prefix={<MobileOutlined />}
                onPressEnter={handleOTPStart}
              />
              <Text type="secondary" className="text-xs mt-1 block">
                Enter the account phone number (Iranian format)
              </Text>
            </div>
            {panelRole && (
              <Alert
                message={`This account will be added as ${panelRole}`}
                type="info"
                showIcon
                style={{ marginTop: 8 }}
              />
            )}
            <Button
              type="primary"
              size="large"
              block
              loading={otpLoading}
              onClick={handleOTPStart}
              style={{ background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)', border: 'none', height: 44 }}
            >
              Send OTP Code
            </Button>
          </div>
        )}

        {otpStep === 1 && (
          <div className="space-y-4">
            <Alert
              message={`SMS sent to ${otpPhone}`}
              description="Enter the 6-digit verification code you received."
              type="info"
              showIcon
            />
            <div>
              <label className="block text-sm font-medium mb-1">Verification Code</label>
              <Input
                size="large"
                placeholder="123456"
                value={otpCode}
                onChange={e => setOtpCode(e.target.value)}
                prefix={<SafetyOutlined />}
                maxLength={6}
                onPressEnter={handleOTPVerify}
                autoFocus
                style={{ fontSize: '1.5em', textAlign: 'center', letterSpacing: '0.5em' }}
              />
            </div>
            <Space className="w-full" direction="vertical">
              <Button
                type="primary"
                size="large"
                block
                loading={otpLoading}
                onClick={handleOTPVerify}
                style={{ background: 'linear-gradient(135deg, #11998e 0%, #38ef7d 100%)', border: 'none', height: 44 }}
              >
                Verify & Add Account
              </Button>
              <Button size="small" type="link" onClick={() => { setOtpStep(0); setOtpCode(''); }}>
                ← Back to phone number
              </Button>
            </Space>
          </div>
        )}
      </Modal>

      {/* Token-based Add Modal — No role selector, auto-determined */}
      <Modal
        title={
          <Space>
            <span>Add Account by Token</span>
            {panelRole && <Tag color={panelRole === 'CLIENT' ? 'purple' : 'blue'}>{panelRole}</Tag>}
          </Space>
        }
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
          {panelRole && (
            <Alert
              message={`This account will be added as ${panelRole}`}
              type="info"
              showIcon
              style={{ marginBottom: 16 }}
            />
          )}
          <Form.Item
            name="token"
            label="Bale JWT Token"
            rules={[{ required: true, message: 'Please input the JWT token' }]}
          >
            <TextArea rows={4} placeholder="Paste the access_token here..." />
          </Form.Item>
          <Form.Item className="mb-0 flex justify-end">
            <Space>
              <Button onClick={() => setShowAdd(false)}>Cancel</Button>
              <Button type="primary" htmlType="submit" loading={loading}>
                Add Account
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Modal>

      <AccountDetailsDrawer
        accountId={selectedAccountId}
        onClose={() => setSelectedAccountId(null)}
        onUpdate={() => {
          load();
        }}
      />
    </div>
  );
}
