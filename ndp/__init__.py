import datetime
import json
import os
import re
import requests
import threading
from typing import Optional, Dict, Any

from mcdreforged.api.all import *

PLUGIN_METADATA = {
    "id": "ndp",
    "version": "1.7.7",
    "author": "EXE_autumnwind",
    "link": "https://github.com/No-Danger-Player-Project/NDP-MCDR"
}

class Config(Serializable):
    api_url: str = 'https://api.ndp.codewaves.cn'
    secret_token: str = 'ndp_pwd_114514'
    sync_interval: int = 30
    check_localhost: bool = True
    ip_record_interval: int = 30
    check_update: bool = True
    auto_ban: bool = True
    synclog: bool = True

class BanData:
    def __init__(self, server: PluginServerInterface):
        self.server = server
        self.bans = {
            'ip_bans': {},
            'player_bans': {},
            'last_sync': None
        }
        self.ip_records = {}
        self.online_players = set()
        self._init_data_files()

    def _init_data_files(self):
        os.makedirs(self.server.get_data_folder(), exist_ok=True)
        self._ensure_file('bans.json', self.bans)
        self._ensure_file('ips.json', {})
        self.load_data()

    def _ensure_file(self, filename: str, default_data: dict):
        path = os.path.join(self.server.get_data_folder(), filename)
        if not os.path.exists(path):
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(default_data, f, indent=2, ensure_ascii=False)

    def load_data(self):
        try:
            with open(self._get_data_path('bans.json'), 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.bans = {
                    'ip_bans': data.get('ip_bans', {}),
                    'player_bans': data.get('player_bans', {}),
                    'last_sync': data.get('last_sync')
                }
        except Exception as e:
            self.server.logger.error(f'加载封禁数据失败: {str(e)}')
            self.bans = {
                'ip_bans': {},
                'player_bans': {},
                'last_sync': None
            }

        try:
            with open(self._get_data_path('ips.json'), 'r', encoding='utf-8') as f:
                self.ip_records = json.load(f)
        except Exception as e:
            self.server.logger.error(f'加载IP记录失败: {str(e)}')
            self.ip_records = {}

    def save_data(self):
        try:
            with open(self._get_data_path('bans.json'), 'w', encoding='utf-8') as f:
                json.dump({
                    'ip_bans': self.bans.get('ip_bans', {}),
                    'player_bans': self.bans.get('player_bans', {}),
                    'last_sync': self.bans.get('last_sync')
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.server.logger.error(f'保存封禁数据失败: {str(e)}')

    def save_ip_data(self):
        try:
            with open(self._get_data_path('ips.json'), 'w', encoding='utf-8') as f:
                json.dump(self.ip_records, f, indent=2, ensure_ascii=False)
        except Exception as e:
            self.server.logger.error(f'保存IP记录失败: {str(e)}')

    def _get_data_path(self, filename: str) -> str:
        return os.path.join(self.server.get_data_folder(), filename)

    def is_ip_banned(self, ip: str) -> bool:
        return ip in self.bans.get('ip_bans', {})

    def is_player_banned(self, player: str) -> bool:
        return player in self.bans.get('player_bans', {})

    def record_ip(self, player: str, ip: str):
        if player not in self.ip_records:
            self.ip_records[player] = []
        if ip not in self.ip_records[player]:
            self.ip_records[player].append(ip)
        self.save_ip_data()

    def get_player_ip(self, player: str) -> Optional[str]:
        ips = self.ip_records.get(player, [])
        return ips[-1] if ips else None

    def update_online_status(self, player: str, online: bool):
        if online:
            self.online_players.add(player)
        else:
            self.online_players.discard(player)

    def is_player_online(self, player: str) -> bool:
        try:
            return self.server.get_plugin_instance('online_player_api').check_online(player)
        except:
            return player in self.online_players

class NDPBanSystem:
    def __init__(self, server: PluginServerInterface):
        self.server = server
        self.config = Config()
        self.ban_data = BanData(server)
        self.__sync_timer = None
        self.__ip_record_timer = None
        self.__running = False
        self.ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        self.ip_logger = None
        self.online_player_api = None
        self.last_update_check = None
        self.load_config()

    def load_config(self):
        try:
            self.config = self.server.load_config_simple(
                file_name='config/ndp_config.json',
                target_class=Config,
                default_config=Config().serialize()
            )
        except Exception as e:
            self.server.logger.error(f'加载配置失败: {str(e)}，使用默认配置')

    def on_load(self, server: PluginServerInterface):
        try:
            self.ip_logger = server.get_plugin_instance('player_ip_logger')
            if self.ip_logger is None:
                server.logger.warning('缺少Player IP Logger,使用Minecraft Data API')
        
            self.stop_sync_timer()
            self.stop_ip_record_timer()
        
            self.register_commands()
            self.start_sync_timer()
            self.start_ip_record_timer()
        
            threading.Thread(target=self.check_for_updates, daemon=True).start()

            # 修改事件监听器注册方式
            server.register_event_listener(
                'mcdr.player_joined', 
                self.on_player_joined
            )
            server.register_event_listener(
                'mcdr.player_left',
                self.on_player_left
            )
        
            server.register_event_listener(
                'server_startup',
                self.check_all_online_players
            )
        
        except Exception as e:
            raise

    def check_all_online_players(self):
        try:
            if self.online_player_api is not None:
                online_players = self.online_player_api.get_player_list()
            else:
                online_players = self.server.get_plugin_instance('minecraft_data_api').get_server_players()
                
            for player in online_players:
                self.ban_data.update_online_status(player, True)
                if ip := self._get_player_ip(player):
                    self.ban_data.record_ip(player, ip)
            self.check_online_players()
        except Exception as e:
            self.server.logger.error(f'检查在线玩家失败: {str(e)}')

    def register_commands(self):
        def build_command_tree(root: Literal):
            return (
                root.then(Literal('help').runs(self.cmd_show_help))
                .then(Literal('ban').then(
                    Text('player').then(
                        GreedyText('reason').runs(self._cmd_ban_player)
                    )
                ))
                .then(Literal('pardon').then(
                    Text('player').then(
                        GreedyText('reason').runs(self._cmd_pardon_player)
                    )
                ))
                .then(Literal('sync').runs(self._cmd_sync_bans))
                .then(Literal('reload').runs(self._cmd_reload_config))
                .then(Literal('ip').then(
                    Text('player').runs(self._cmd_show_ip)
                ))
                .then(Literal('status').runs(self._cmd_show_status))
                .then(Literal('checkupdate').runs(self._cmd_check_update))
                .then(Literal('cu').runs(self._cmd_check_update))
            )
        
        cmd = Literal('!!ndp').requires(lambda src: src.has_permission(3))
        build_command_tree(cmd).runs(self.cmd_show_help)
        self.server.register_command(cmd)
        
        alias_cmd = Literal('!!NDP').requires(lambda src: src.has_permission(3))
        build_command_tree(alias_cmd).runs(self.cmd_show_help)
        self.server.register_command(alias_cmd)

    def cmd_show_help(self, source: CommandSource):
        help_msg = [
            '§6=== NDP封禁系统帮助 ===',
            '§b!!ndp help §f- 显示帮助信息',
            '§b!!ndp ban <玩家> [原因] §f- 封禁玩家',
            '§b!!ndp pardon <玩家> [原因] §f- 解封玩家',
            '§b!!ndp sync §f- 手动同步封禁列表',
            '§b!!ndp reload §f- 重载配置文件',
            '§b!!ndp ip <玩家> §f- 查询玩家IP',
            '§b!!ndp status §f- 查看系统状态',
            '§b!!ndp checkupdate §f- 检查更新',
            f'§a同步间隔: {self.config.sync_interval}秒',
            f'§a自动封禁: {"开启" if self.config.auto_ban else "关闭"}',
            f'§a显示同步提示: {"开启" if self.config.synclog else "关闭"}',
            f'§a当前版本: v{PLUGIN_METADATA["version"]}'
        ]
        source.reply('\n'.join(help_msg))

    def _cmd_ban_player(self, source: CommandSource, ctx: CommandContext):
        player = ctx['player']
        reason = ctx.get('reason', '由管理员封禁')
        
        if ip := self._get_player_ip(player):
            try:
                response = requests.post(
                    f'{self.config.api_url}/add_ban',
                    json={
                        'verification': self.config.secret_token,
                        'action': "ban",
                        'username': player,
                        'ip': ip,
                        'cause': reason
                    },
                    timeout=10
                )
                response.raise_for_status()
                
                self.sync_bans()
                self.server.execute(f'ban {player} {reason}')
                source.reply(f'§a[NDP]已向云端服务器发送封禁请求 {player} (IP: {ip})')
                self.server.logger.info(f'已向云端服务器发送封禁请求(玩家 {player} IP: {ip})')
                
                if self.ban_data.is_player_online(player):
                    self.kick_player(player, reason)
            except Exception as e:
                source.reply(f'§c[NDP]向云端服务器发送封禁请求失败: {str(e)}')
                self.server.logger.error(f'向云端服务器发送封禁 玩家:{player}请求失败: {str(e)}')
        else:
            source.reply(f'§c[NDP]找不到玩家 {player} 的IP记录')
            self.server.logger.warning(f'找不到玩家 {player} 的IP记录')

    def _cmd_pardon_player(self, source: CommandSource, ctx: CommandContext):
        player = ctx['player']
        reason = ctx.get('reason', '由管理员解封')
        
        try:
            ip = self._get_player_ip(player) or ""
            
            response = requests.post(
                f'{self.config.api_url}/add_ban',
                json={
                    'verification': self.config.secret_token,
                    'action': "remove",
                    'username': player,
                    'ip': ip,
                    'cause': reason
                },
                timeout=10
            )
            response.raise_for_status()
            
            self.sync_bans()
            self.server.execute(f'pardon {player}')
            source.reply(f'§a[NDP]已向云端服务器发送解封请求 {player}')
            self.server.logger.info(f'已向云端服务器发送解封请求(玩家 {player})')
        except Exception as e:
            source.reply(f'§c[NDP]向云端服务器发送解封请求失败: {str(e)}')
            self.server.logger.error(f'向云端服务器发送解封玩家 {player} 请求失败: {str(e)}')

    def _cmd_sync_bans(self, source: CommandSource, ctx: CommandContext = None):
        self.sync_bans(source, show_message=True)

    def _cmd_reload_config(self, source: CommandSource, ctx: CommandContext = None):
        self.load_config()
        self.stop_sync_timer()
        self.stop_ip_record_timer()
        self.start_sync_timer()
        self.start_ip_record_timer()
        source.reply('§a[NDP]配置已重新加载')
        self.server.logger.info('NDP配置已重新加载')

    def _cmd_show_ip(self, source: CommandSource, ctx: CommandContext):
        player = ctx['player']
        if ip := self._get_player_ip(player):
            source.reply(f'§a[NDP]玩家 {player} 的IP: {ip}')
            self.server.logger.info(f'查询玩家 {player} 的IP: {ip}')
        else:
            source.reply(f'§c[NDP]找不到玩家 {player} 的IP记录')
            self.server.logger.warning(f'找不到玩家 {player} 的IP记录')

    def _cmd_show_status(self, source: CommandSource, ctx: CommandContext):
        try:
            status = [
                '§6=== NDP封禁系统状态 ===',
                f'§a当前版本: v{PLUGIN_METADATA["version"]}',
                f'§aAPI地址: {self.config.api_url}',
                f'§a封禁IP数量: {len(self.ban_data.bans.get("ip_bans", {}))}',
                f'§a封禁玩家数量: {len(self.ban_data.bans.get("player_bans", {}))}',
                f'§a在线玩家数量: {len(self.ban_data.online_players)}',
                f'§a最后同步时间: {self.ban_data.bans.get("last_sync", "从未同步")}',
                f'§aIP记录方式: {"IP Logger" if self.ip_logger else "Minecraft Data API"}',
                f'§a自动封禁: {"开启" if self.config.auto_ban else "关闭"}',
                f'§a显示同步提示: {"开启" if self.config.synclog else "关闭"}',
                f'§a检查更新: {"开启" if self.config.check_update else "关闭"}'
            ]
            source.reply('\n'.join(status))
        except Exception as e:
            self.server.logger.error(f'显示状态时出错: {str(e)}')
            source.reply('§c[NDP]获取状态信息失败')

    def _cmd_check_update(self, source: CommandSource, ctx: CommandContext = None):
        threading.Thread(target=self.check_for_updates, args=(source,), daemon=True).start()

    def _get_player_ip(self, player: str) -> Optional[str]:
        if not isinstance(player, str) or not player:
            return None
            
        try:
            if ip := self.ban_data.get_player_ip(player):
                return ip
            
            if self.ip_logger is not None:
                try:
                    ips = self.ip_logger.get_player_ips(player)
                    if ips and len(ips) > 0:
                        return ips[-1]
                except Exception as e:
                    self.server.logger.warning(f'从IP Logger获取玩家 {player} IP失败: {str(e)}')
            
            try:
                info = self.server.get_plugin_instance('minecraft_data_api').get_player_info(player)
                if info and 'ip' in info and self.ip_pattern.match(info['ip']):
                    return info['ip']
            except Exception as e:
                self.server.logger.warning(f'从Minecraft Data API获取玩家 {player} IP失败: {str(e)}')
            
            return None
        except Exception as e:
            self.server.logger.error(f'获取玩家 {player} IP失败: {str(e)}')
            return None

    def start_sync_timer(self):
        if self.__running:
            return
            
        self.__running = True
        self.__schedule_next_sync()

    def __schedule_next_sync(self):
        if not self.__running:
            return
            
        self.__sync_timer = threading.Timer(
            self.config.sync_interval,
            self.__sync_task
        )
        self.__sync_timer.start()

    def __sync_task(self):
        try:
            self.sync_bans(show_message=False)
        except Exception as e:
            self.server.logger.error(f'同步失败: {str(e)}')
        finally:
            self.__schedule_next_sync()

    def stop_sync_timer(self):
        self.__running = False
        if self.__sync_timer is not None:
            self.__sync_timer.cancel()
            self.__sync_timer = None

    def start_ip_record_timer(self):
        self.__schedule_next_ip_record()

    def __schedule_next_ip_record(self):
        self.__ip_record_timer = threading.Timer(
            self.config.ip_record_interval,
            self.__ip_record_task
        )
        self.__ip_record_timer.start()

    def __ip_record_task(self):
        try:
            self.record_all_online_ips()
        except Exception as e:
            self.server.logger.error(f'记录IP失败: {str(e)}')
        finally:
            self.__schedule_next_ip_record()

    def stop_ip_record_timer(self):
        if self.__ip_record_timer is not None:
            self.__ip_record_timer.cancel()
            self.__ip_record_timer = None

    def record_all_online_ips(self):
        try:
            if self.online_player_api is not None:
                online_players = self.online_player_api.get_player_list()
            else:
                online_players = list(self.ban_data.online_players)
                
            for player in online_players:
                if ip := self._get_player_ip(player):
                    self.ban_data.record_ip(player, ip)
        except Exception as e:
            self.server.logger.error(f'记录在线玩家IP时出错: {str(e)}')

    def on_player_joined(self, server: PluginServerInterface, player: str, info: dict, *args):
        self.ban_data.update_online_status(player, True)
    
        if ip := self._get_player_ip(player):
            self.ban_data.record_ip(player, ip)
        
            if (ip == '127.0.0.1' or ip == '::1') and self.config.check_localhost:
                self.server.logger.warning('检测到本地连接，请确保已正确配置proxy protocol')
        
            try:
                response = requests.get(
                    f'{self.config.api_url}/bans',
                    headers={'Authorization': f'Bearer {self.config.secret_token}'},
                    timeout=5
                )
                response.raise_for_status()
                data = response.json()
                
                for banned_ip in data.get('active_ips', []):
                    if ip == banned_ip.get('ip'):
                        reason = banned_ip.get('cause', '你已被封禁')
                        related_players = banned_ip.get('players', [])
                        
                        kick_msg = [
                            '§c§l[NDP] 检测到被封禁玩家',
                            f'§7玩家: §f{player}',
                            f'§7IP地址: §f{ip}',
                            f'§7封禁原因: §c{reason}',
                        ]
                        
                        if related_players:
                            kick_msg.append(f'§7关联玩家: §f{", ".join(related_players)}')
                        
                        kick_msg.append('§7如有疑问请联系NDP管理人员')
                        self.kick_player(player, '\n'.join(kick_msg))
                        
                        announce_msg = [
                            '§c§l[NDP] 检测到被封禁玩家',
                            f'§7玩家: §f{player}',
                            f'§7IP地址: §f{ip}',
                        ]
                        self.server.say('\n'.join(announce_msg))
                        self.server.logger.info(f'检测到被封禁玩家 {player} (IP: {ip})')
                        return
                
                for banned_player in data.get('active_players', []):
                    if player == banned_player.get('username'):
                        reason = banned_player.get('cause', '你已被封禁')
                        banned_ip = banned_player.get('ip', '')
                        
                        kick_msg = [
                            '§c§l[NDP] 检测到封禁账号',
                            f'§7玩家: §f{player}',
                            f'§7封禁原因: §c{reason}',
                        ]
                        
                        if banned_ip:
                            kick_msg.append(f'§7关联IP: §f{banned_ip}')
                        
                        kick_msg.append('§7如有疑问请联系NDP管理人员')
                        self.kick_player(player, '\n'.join(kick_msg))
                        
                        announce_msg = [
                            '§c§l[NDP] 检测到被封禁玩家',
                            f'§7玩家: §f{player}',
                        ]
                        self.server.say('\n'.join(announce_msg))
                        self.server.logger.info(f'检测到被封禁玩家 {player}')
                        return
            
            except Exception as e:
                self.server.logger.warning(f'无法连接到NDP服务器: {str(e)}, 将使用本地数据检查')
                
                if self.ban_data.is_ip_banned(ip):
                    kick_msg = [
                        '§c§l[NDP] 检测到被封禁玩家',
                        f'§7玩家: §f{player}',
                        f'§7IP: §f{ip}',
                        '§7封禁原因: §c你的IP已被NDP系统封禁',
                        '§7如有疑问请联系NDP管理人员'
                    ]
                    self.kick_player(player, '\n'.join(kick_msg))
                    self.server.logger.info(f'检测到被封禁玩家')
                elif self.ban_data.is_player_banned(player):
                    kick_msg = [
                        '§c§l[NDP] 检测到封禁账号',
                        f'§7玩家: §f{player}',
                        '§7封禁原因: §c你已被NDP系统封禁',
                        '§7如有疑问请联系NDP管理人员'
                    ]
                    self.kick_player(player, '\n'.join(kick_msg))
                    self.server.logger.info(f'检测到被封禁玩家 {player}')

    def on_player_left(self, server: PluginServerInterface, player: str, *args):
        self.ban_data.update_online_status(player, False)

    def sync_bans(self, source: Optional[CommandSource] = None, show_message: bool = True):
        last_sync = self.ban_data.bans.get('last_sync', '从未同步')
    
        try:
            response = requests.get(
                f'{self.config.api_url}/bans',
                headers={'Authorization': f'Bearer {self.config.secret_token}'},
                timeout=10
            )
            response.raise_for_status()
            data = response.json()

            ip_bans = {}
            player_bans = {}
            banned_ips = []
            banned_players = []
            
            for ip_ban in data.get('active_ips', []):
                ip = ip_ban.get('ip')
                if ip:
                    ip_bans[ip] = {
                        'cause': ip_ban.get('cause', ''),
                        'players': ip_ban.get('players', []),
                        'timestamp': ip_ban.get('timestamp', '')
                    }
                    if self.config.auto_ban and ip not in self.ban_data.bans['ip_bans']:
                        try:
                            self.server.execute(f'ban-ip {ip}')
                            banned_ips.append(ip)
                        except Exception as e:
                            self.server.logger.error(f'自动封禁IP {ip} 失败: {str(e)}')
            
            for player_ban in data.get('active_players', []):
                username = player_ban.get('username')
                if username:
                    player_bans[username] = {
                        'cause': player_ban.get('cause', ''),
                        'ip': player_ban.get('ip', ''),
                        'timestamp': player_ban.get('timestamp', '')
                    }
                    if self.config.auto_ban and username not in self.ban_data.bans['player_bans']:
                        try:
                            self.server.execute(f'ban {username}')
                            banned_players.append(username)
                        except Exception as e:
                            self.server.logger.error(f'自动封禁玩家 {username} 失败: {str(e)}')

            self.ban_data.bans = {
                'ip_bans': ip_bans,
                'player_bans': player_bans,
                'last_sync': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            self.ban_data.save_data()

            if show_message and source is not None:
                msg = f'§a[NDP] 同步完成 (封禁IP: {len(ip_bans)}, 封禁玩家: {len(player_bans)})'
                if self.config.auto_ban:
                    if banned_ips or banned_players:
                        msg += '\n§a自动封禁: '
                        if banned_ips:
                            msg += f'IP({len(banned_ips)}) '
                        if banned_players:
                            msg += f'玩家({len(banned_players)})'
                    else:
                        msg += '\n§a没有新的封禁需要添加'
                source.reply(msg)
                
            if self.config.synclog:
                self.server.logger.info(f'封禁列表同步成功 (IP封禁: {len(ip_bans)}, 玩家封禁: {len(player_bans)})')
                if self.config.auto_ban:
                    if banned_ips:
                        self.server.logger.info(f'自动封禁了 {len(banned_ips)} 个IP地址')
                    if banned_players:
                        self.server.logger.info(f'自动封禁了 {len(banned_players)} 个玩家')

            self.check_online_players()

        except requests.exceptions.RequestException as e:
            error_msg = f'连接NDP服务器失败: {str(e)}'
            if show_message and source is not None:
                source.reply(f'§c[NDP] {error_msg}')
            self.server.logger.error(error_msg)
        except json.JSONDecodeError as e:
            error_msg = f'解析NDP服务器响应失败: {str(e)}'
            if show_message and source is not None:
                source.reply(f'§c[NDP] {error_msg}')
            self.server.logger.error(error_msg)
        except Exception as e:
            error_msg = f'同步过程中发生未知错误: {str(e)}'
            if show_message and source is not None:
                source.reply(f'§c[NDP] {error_msg}')
            self.server.logger.error(error_msg)

    def check_online_players(self):
        kicked_players = []
    
        try:
            response = requests.get(
                f'{self.config.api_url}/bans',
                headers={'Authorization': f'Bearer {self.config.secret_token}'},
                timeout=5
            )
            response.raise_for_status()
            data = response.json()
            
            banned_ips = {ip_data['ip']: ip_data for ip_data in data.get('active_ips', [])}
            banned_players = {player_data['username']: player_data for player_data in data.get('active_players', [])}
            
            if self.online_player_api is not None:
                online_players = self.online_player_api.get_player_list()
            else:
                online_players = list(self.ban_data.online_players)
                
            for player in online_players:
                ip = self._get_player_ip(player)
                
                if ip and ip in banned_ips:
                    ban_info = banned_ips[ip]
                    reason = ban_info.get('cause', '你已被封禁')
                    related_players = ban_info.get('players', [])
                    
                    kick_msg = [
                        '§c§l[NDP] 检测到被封禁玩家',
                        f'§7玩家: §f{player}',
                        f'§7IP地址: §f{ip}',
                        f'§7封禁原因: §c{reason}',
                        f'§7封禁类型: §cIP封禁'
                    ]
                    
                    if related_players:
                        kick_msg.append(f'§7关联玩家: §f{", ".join(related_players)}')
                    
                    kick_msg.append('§7如有疑问请联系NDP管理人员')
                    self.kick_player(player, '\n'.join(kick_msg))
                    kicked_players.append(f'§c{player}§7(您的IP段§f{ip}§7被封禁,如有疑问请联系NDP管理人员)')
                    continue
                    
                if player in banned_players:
                    ban_info = banned_players[player]
                    reason = ban_info.get('cause', '你已被封禁')
                    banned_ip = ban_info.get('ip', '')
                    
                    kick_msg = [
                        '§c§l[NDP] 检测到被封禁玩家',
                        f'§7玩家: §f{player}',
                        f'§7封禁原因: §c{reason}',
                        f'§7封禁类型: §c玩家名封禁'
                    ]
                    
                    if banned_ip:
                        kick_msg.append(f'§7关联IP: §f{banned_ip}')
                    
                    kick_msg.append('§7如有疑问请联系NDP管理人员')
                    self.kick_player(player, '\n'.join(kick_msg))
                    kicked_players.append(f'§c{player}§7(你已被封禁,如有疑问请联系NDP管理人员)')
                    
        except Exception as e:
            self.server.logger.warning(f'在线检查失败: {str(e)}，将使用本地数据检查')
            
            if self.online_player_api is not None:
                online_players = self.online_player_api.get_player_list()
            else:
                online_players = list(self.ban_data.online_players)
                
            for player in online_players:
                ip = self._get_player_ip(player)
                
                if self.ban_data.is_player_banned(player):
                    reason = self.ban_data.bans['player_bans'].get(player, '你已被NDP系统封禁')
                    
                    kick_msg = [
                        '§c§l[NDP] 检测到封禁账号',
                        f'§7玩家: §f{player}',
                        f'§7封禁原因: §c{reason}',
                        '§7如有疑问请联系NDP管理人员'
                    ]
                    self.kick_player(player, '\n'.join(kick_msg))
                    kicked_players.append(f'§c{player}§7(你已被封禁,如有疑问请联系NDP管理人员)')
                elif ip and self.ban_data.is_ip_banned(ip):
                    reason = self.ban_data.bans['ip_bans'].get(ip, '你的IP已被NDP系统封禁')
                    
                    kick_msg = [
                        '§c§l[NDP] 检测到被封禁玩家',
                        f'§7玩家: §f{player}',
                        f'§7IP: §f{ip}',
                        f'§7封禁原因: §c{reason}',
                        '§7如有疑问请联系NDP管理人员'
                    ]
                    self.kick_player(player, '\n'.join(kick_msg))
                    kicked_players.append(f'§c{player}§7(您的IP段§f{ip}§7被封禁,如有疑问请联系NDP管理人员)')
    
        if kicked_players:
            announce_msg = [
                '§c§l[NDP] 检测到被封禁玩家',
                f'§7已踢出: {", ".join(kicked_players)}'
            ]
            self.server.say('\n'.join(announce_msg))
            self.server.logger.info(f'已踢出封禁玩家: {", ".join([p.replace("§", "&") for p in kicked_players])}')

    def kick_player(self, player: str, reason: str):
        self.server.execute(f'kick {player} {reason}')
        self.server.logger.info(f'已踢出玩家 {player}: {reason}')

    def check_for_updates(self, source: CommandSource = None):
        if not self.config.check_update:
            return
    
        def send_message(msg: str):
            if source is not None and source.is_player:
                source.reply(msg)
            self.server.logger.info(msg.replace('§a', '').replace('§e', '').replace('§c', ''))
    
        try:
            if source:
                source.reply("§a[NDP] 正在检查更新...")
            self.server.logger.info("正在检查NDP更新...")
            
            response = requests.get(
                'https://api.github.com/repos/No-Danger-Player-Project/NDP-MCDR/releases/latest',
                timeout=30
            )
            response.raise_for_status()
            data = response.json()
        
            latest_version = data['tag_name'].lstrip('v')
            current_version = PLUGIN_METADATA['version']
        
            if latest_version > current_version:
                messages = [
                    "§a[NDP] 发现新版本!",
                    f"§a当前版本: v{current_version}",
                    f"§a最新版本: v{latest_version}",
                    f"§a更新内容: {data.get('body', '无描述')}",
                    f"§a下载地址: https://mcdreforged.com/plugin/ndp/release/{latest_version}",
                    RText("§b[§d安装更新§b]")
                        .set_click_event(RAction.suggest_command, f'!!MCDR plg install ndp=={latest_version}')
                        .set_hover_text("§b点击填充命令到聊天栏")
                    
                ]
                if source:
                    for msg in messages:
                        source.reply(msg)
                self.server.logger.info(f"发现新版本NDP: v{latest_version} (当前版本: v{current_version})")
            else:
                if source:
                    source.reply(f"§a[NDP] 当前已是最新版本 (v{current_version})")
                self.server.logger.info(f"NDP当前已是最新版本 (v{current_version})")
            
        except Exception as e:
            if source:
                source.reply(f"§c[NDP] 检查更新失败: {str(e)}")
            self.server.logger.error(f"检查更新失败: {str(e)}")

ndp_system = None

def on_load(server: PluginServerInterface, old):
    global ndp_system
    ndp_system = NDPBanSystem(server)
    ndp_system.on_load(server)

def on_unload(server: PluginServerInterface):
    global ndp_system
    if ndp_system:
        ndp_system.stop_sync_timer()
        ndp_system.stop_ip_record_timer()
