#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sqlite3
import functools
import json
from flask import Flask, request, jsonify, session, url_for, render_template
from flask_cors import CORS

import cloudflare
from alibabacloud_domain20180129.client import Client as AliDomainClient
from alibabacloud_alidns20150109.client import Client as AliDnsClient
from alibabacloud_alidns20150109 import models as ali_dns_models
from alibabacloud_domain20180129 import models as ali_domain_models
from alibabacloud_tea_openapi import models as open_api_models
from tencentcloud.common import credential
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.domain.v20180808 import domain_client as tx_domain_client, models as tx_domain_models
from tencentcloud.dnspod.v20210323 import dnspod_client as tx_dns_client, models as tx_dns_models

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, static_folder=os.path.join(basedir, 'static'), template_folder=os.path.join(basedir, 'templates'))
CORS(app, supports_credentials=True)
app.secret_key = os.urandom(24)

DB_FILE = os.path.join(basedir, 'dns_records.db')
ADMIN_USER = 'admin'
ADMIN_PASS = '123456'

# ========== Base de Datos ==========
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS records (id INTEGER PRIMARY KEY, provider TEXT, record_id TEXT, domain TEXT, rr TEXT,
            type TEXT, value TEXT, ttl INTEGER, status TEXT, created_at TEXT, UNIQUE(provider, record_id))
        ''')
        db.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)')
        for key in ['ALI_KEY', 'ALI_SECRET', 'TX_ID', 'TX_KEY', 'CF_API_TOKEN']:
            db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, ''))
        
        db.execute('CREATE TABLE IF NOT EXISTS preferences (key TEXT PRIMARY KEY, value TEXT)')
        default_columns = "provider,rr,value,status,created_at"
        db.execute("INSERT OR IGNORE INTO preferences (key, value) VALUES (?, ?)", ('visible_columns', default_columns))
        db.commit()

def get_settings():
    with get_db() as db: return {row['key']: row['value'] for row in db.execute("SELECT key, value FROM settings").fetchall()}

def update_settings(data):
    with get_db() as db:
        for key, value in data.items(): db.execute("UPDATE settings SET value = ? WHERE key = ?", (value, key))
        db.commit()

# ========== Gestor de APIs de la Nube ==========
class CloudManager:
    def __init__(self, settings):
        if settings.get('ALI_KEY') and settings.get('ALI_SECRET'):
            ali_config = open_api_models.Config(access_key_id=settings.get('ALI_KEY'), access_key_secret=settings.get('ALI_SECRET'))
            ali_config.endpoint = 'alidns.cn-hangzhou.aliyuncs.com'
            self.ali_dns = AliDnsClient(ali_config)
            ali_domain_config = open_api_models.Config(access_key_id=settings.get('ALI_KEY'), access_key_secret=settings.get('ALI_SECRET'))
            ali_domain_config.endpoint = 'domain.aliyuncs.com'
            self.ali_domain = AliDomainClient(ali_domain_config)
        if settings.get('TX_ID') and settings.get('TX_KEY'):
            cred = credential.Credential(settings.get('TX_ID'), settings.get('TX_KEY'))
            http_profile = HttpProfile(endpoint="dnspod.tencentcloudapi.com")
            self.tx_dns = tx_dns_client.DnspodClient(cred, "", ClientProfile(httpProfile=http_profile))
            domain_http_profile = HttpProfile(endpoint="domain.tencentcloudapi.com")
            self.tx_domain = tx_domain_client.DomainClient(cred, "", ClientProfile(httpProfile=domain_http_profile))
        if settings.get('CF_API_TOKEN'):
            self.cf = cloudflare.Cloudflare(api_token=settings.get('CF_API_TOKEN'))

    def sync_all(self):
        all_records = []
        sync_errors = []
        
        if hasattr(self, 'ali_domain'):
            try:
                ali_domains = []; page_num = 1
                while True:
                    req_d = ali_domain_models.QueryDomainListRequest(page_num=page_num, page_size=100); resp_d = self.ali_domain.query_domain_list(req_d)
                    current_page_domains = resp_d.body.data.domain
                    if not current_page_domains: break
                    for d in current_page_domains: ali_domains.append(d.domain_name)
                    if len(current_page_domains) < 100: break
                    page_num += 1
                for domain in ali_domains:
                    req_r = ali_dns_models.DescribeDomainRecordsRequest(domain_name=domain, page_size=500); resp_r = self.ali_dns.describe_domain_records(req_r)
                    for r in resp_r.body.domain_records.record:
                        all_records.append({'provider': 'aliyun', 'record_id': r.record_id, 'domain': domain, 'rr': r.rr, 'type': r.type, 'value': r.value, 'ttl': r.ttl, 'status': r.status, 'created_at': r.create_timestamp})
            except Exception as e: sync_errors.append(f"Aliyun: {e}")

        if hasattr(self, 'tx_domain'):
            try:
                req_d = tx_domain_models.DescribeDomainNameListRequest(Limit=100); resp_d = self.tx_domain.DescribeDomainNameList(req_d)
                domains = [d.DomainName for d in resp_d.DomainInfoSet]
                for domain in domains:
                    req_r = tx_dns_models.DescribeRecordListRequest(Domain=domain, Limit=3000); resp_r = self.tx_dns.DescribeRecordList(req_r)
                    for r in resp_r.RecordList:
                        all_records.append({'provider': 'tencent', 'record_id': str(r.RecordId), 'domain': domain, 'rr': r.Name, 'type': r.Type, 'value': r.Value, 'ttl': r.TTL, 'status': r.Status, 'created_at': r.created_on})
            except Exception as e: sync_errors.append(f"Tencent: {e}")

        if hasattr(self, 'cf'):
            try:
                zones = self.cf.zones.get(params={'per_page': 100})
                for zone in zones:
                    dns_records = self.cf.dns.records.list(zone_id=zone['id'], params={'per_page': 100})
                    for record in dns_records:
                        rr = record['name'].replace(f".{zone['name']}", '') if record['name'] != zone['name'] else '@'
                        all_records.append({'provider': 'cloudflare', 'record_id': record['id'], 'domain': zone['name'], 'rr': rr, 'type': record['type'], 'value': record['content'], 'ttl': record['ttl'], 'status': 'Proxied' if record['proxied'] else 'DNS Only', 'created_at': record['created_on']})
            except Exception as e: sync_errors.append(f"Cloudflare: {e}")

        with get_db() as db:
            existing_ids = {f"{row['provider']}-{row['record_id']}" for row in db.execute("SELECT provider, record_id FROM records").fetchall()}
            for r in all_records:
                current_id = f"{r['provider']}-{r['record_id']}"
                if current_id in existing_ids:
                    db.execute("UPDATE records SET domain=?, rr=?, type=?, value=?, ttl=?, status=?, created_at=? WHERE provider=? AND record_id=?", (r['domain'], r['rr'], r['type'], r['value'], r['ttl'], r['status'], r['created_at'], r['provider'], r['record_id'])); existing_ids.remove(current_id)
                else:
                    db.execute("INSERT INTO records (provider, record_id, domain, rr, type, value, ttl, status, created_at) VALUES (?,?,?,?,?,?,?,?,?)", (r['provider'], r['record_id'], r['domain'], r['rr'], r['type'], r['value'], r['ttl'], r['status'], r['created_at']))
            if existing_ids:
                for combined_id in existing_ids: provider, record_id = combined_id.split('-', 1); db.execute("DELETE FROM records WHERE provider=? AND record_id=?", (provider, record_id))
            db.commit()
        return len(all_records), sync_errors

    def add_record(self, provider, domain, rr, type_, value, ttl, proxied=False):
        if provider == 'aliyun': self.ali_dns.add_domain_record(ali_dns_models.AddDomainRecordRequest(domain_name=domain, rr=rr, type=type_, value=value, ttl=ttl))
        elif provider == 'tencent': self.tx_dns.CreateRecord(tx_dns_models.CreateRecordRequest(Domain=domain, SubDomain=rr, RecordType=type_, Value=value, TTL=int(ttl), RecordLine='默认'))
        elif provider == 'cloudflare':
            zones = self.cf.zones.get(params={'name': domain}); zone_id = zones[0]['id']
            record_name = rr if rr != '@' else domain
            self.cf.dns.records.create(zone_id=zone_id, data={'name': record_name, 'type': type_, 'content': value, 'ttl': int(ttl), 'proxied': proxied})

    def delete_record(self, provider, domain, record_id):
        if provider == 'aliyun': self.ali_dns.delete_domain_record(ali_dns_models.DeleteDomainRecordRequest(record_id=record_id))
        elif provider == 'tencent': self.tx_dns.DeleteRecord(tx_dns_models.DeleteRecordRequest(Domain=domain, RecordId=int(record_id)))
        elif provider == 'cloudflare':
            zones = self.cf.zones.get(params={'name': domain}); zone_id = zones[0]['id']
            self.cf.dns.records.delete(zone_id=zone_id, dns_record_id=record_id)

    def update_record(self, provider, domain, record_id, rr, type_, value, ttl, proxied=False):
        if provider == 'aliyun': self.ali_dns.update_domain_record(ali_dns_models.UpdateDomainRecordRequest(record_id=record_id, rr=rr, type=type_, value=value, ttl=ttl))
        elif provider == 'tencent': self.tx_dns.ModifyRecord(tx_dns_models.ModifyRecordRequest(Domain=domain, RecordId=int(record_id), SubDomain=rr, RecordType=type_, Value=value, TTL=int(ttl), RecordLine='默认'))
        elif provider == 'cloudflare':
            zones = self.cf.zones.get(params={'name': domain}); zone_id = zones[0]['id']
            record_name = rr if rr != '@' else domain
            self.cf.dns.records.update(zone_id=zone_id, dns_record_id=record_id, data={'name': record_name, 'type': type_, 'content': value, 'ttl': int(ttl), 'proxied': proxied})

# ========== Rutas y Lógica de la API ==========
def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'): return jsonify({'status': 'error', 'msg': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated_function
@app.route('/')
def serve_index(): return render_template('index.html')
@app.route('/login')
def serve_login(): return render_template('login.html')
@app.route('/settings')
def serve_settings(): return render_template('settings.html')
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json
    if data.get('username') == ADMIN_USER and data.get('password') == ADMIN_PASS: session['logged_in'] = True; return jsonify({'status': 'success'})
    return jsonify({'status': 'error', 'msg': '账号或密码错误'}), 400
@app.route('/api/logout', methods=['POST'])
def api_logout(): session.pop('logged_in', None); return jsonify({'status': 'success'})
@app.route('/api/session', methods=['GET'])
def api_check_session():
    if session.get('logged_in'): return jsonify({'logged_in': True})
    return jsonify({'logged_in': False}), 401
@app.route('/api/test_credentials', methods=['POST'])
@login_required
def api_test_credentials():
    data = request.json; provider = data.get('provider')
    try:
        if provider == 'aliyun':
            client = AliDomainClient(open_api_models.Config(access_key_id=data['key'], access_key_secret=data['secret'], endpoint='domain.aliyuncs.com'))
            client.query_domain_list(ali_domain_models.QueryDomainListRequest(page_num=1, page_size=1))
        elif provider == 'tencent':
            client = tx_domain_client.DomainClient(credential.Credential(data['id'], data['key']), "", ClientProfile(httpProfile=HttpProfile(endpoint="domain.tencentcloudapi.com")))
            client.DescribeDomainNameList(tx_domain_models.DescribeDomainNameListRequest(Limit=1))
        elif provider == 'cloudflare':
            cf_client = cloudflare.Cloudflare(api_token=data['token'])
            cf_client.user.get()
        return jsonify({'status': 'success', 'msg': '连接成功！'})
    except Exception as e:
        error_message = str(e)
        if "InvalidAccessKeyId" in error_message: error_message = "AccessKey ID o Secret inválido."
        if "Authentication error" in error_message or "Invalid token" in error_message: error_message = "API Token inválido."
        return jsonify({'status': 'error', 'msg': f'连接失败: {error_message}'}), 400
@app.route('/api/create', methods=['POST'])
@login_required
def api_create():
    data = request.form
    try:
        proxied = data.get('proxied') == 'on'
        CloudManager(get_settings()).add_record(data['provider'], data['domain'], data['rr'], data['type'], data['value'], int(data['ttl']), proxied=proxied)
        CloudManager(get_settings()).sync_all()
        return jsonify({'status': 'success'})
    except Exception as e: return jsonify({'status': 'error', 'msg': str(e)}), 500
@app.route('/api/records', methods=['GET'])
@login_required
def api_list_records():
    with get_db() as db:
        query = "SELECT * FROM records ORDER BY created_at DESC"
        records = [dict(row) for row in db.execute(query).fetchall()]
    return jsonify({'data': records})
@app.route('/api/preferences', methods=['GET', 'POST'])
@login_required
def api_preferences():
    if request.method == 'POST':
        data = request.json
        columns_str = ",".join(data.get('columns', []))
        with get_db() as db:
            db.execute("UPDATE preferences SET value = ? WHERE key = ?", (columns_str, 'visible_columns'))
            db.commit()
        return jsonify({'status': 'success', 'msg': '偏好已保存'})
    else: # GET
        with get_db() as db:
            result = db.execute("SELECT value FROM preferences WHERE key = 'visible_columns'").fetchone()
            columns = result['value'].split(',') if result and result['value'] else []
        return jsonify({'visible_columns': columns})
@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def api_settings():
    if request.method == 'POST': update_settings(request.json); return jsonify({'status': 'success', 'msg': '配置已保存！'})
    return jsonify(get_settings())
@app.route('/api/sync', methods=['POST'])
@login_required
def api_sync():
    settings = get_settings()
    if not any(s for s in settings.values() if s):
         return jsonify({'status': 'error', 'msg': '请先配置至少一个云厂商的授权信息'}), 400
    try:
        count, errors = CloudManager(get_settings()).sync_all()
        if not errors: msg = f'同步成功，共处理 {count} 条记录。'
        else: msg = f'同步部分完成，处理了 {count} 条记录。发生以下错误：\n- ' + '\n- '.join(errors)
        return jsonify({'status': 'success', 'msg': msg})
    except Exception as e: return jsonify({'status': 'error', 'msg': str(e)}), 500
@app.route('/api/delete', methods=['POST'])
@login_required
def api_delete():
    data = request.form
    try:
        CloudManager(get_settings()).delete_record(data['provider'], data['domain'], data['record_id'])
        with get_db() as db:
             db.execute("DELETE FROM records WHERE provider=? AND record_id=?", (data['provider'], data['record_id'])); db.commit()
        return jsonify({'status': 'success'})
    except Exception as e: return jsonify({'status': 'error', 'msg': str(e)}), 500
@app.route('/api/update', methods=['POST'])
@login_required
def api_update():
    data = request.form
    try:
        proxied = data.get('proxied') == 'on'
        CloudManager(get_settings()).update_record(
            data['provider'], data['domain'], data['record_id'], data['rr'], 
            data['type'], data['value'], int(data['ttl']),
            proxied=proxied
        )
        CloudManager(get_settings()).sync_all()
        return jsonify({'status': 'success'})
    except Exception as e: 
        print(f"ERROR in /api/update: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'status': 'error', 'msg': str(e)}), 500

if __name__ == '__main__':
    init_db()
    print("Servidor iniciado en http://127.0.0.1:500")
    app.run(host='0.0.0.0', port=500, debug=True)