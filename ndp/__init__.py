import json
import os
import re
import requests
import threading
from typing import Dict, Optional, Any, List

from mcdreforged.api.all import *

PLUGIN_METADATA = {
    "id": "ndp",
    "version": "1.7.0",
    "name": "NDP",
    "description": "适用于MCDR的NDP客户端",
    "author": "EXE_autumnwind",
    "link": "https://github.com/No-Danger-Player-Project/NDP-MCDR",
    "dependencies": {
        "mcdreforged": ">=2.0.0",
        "online_player_api": ">=1.0.0",
        "player_ip_logger": ">=1.0.0",
        "minecraft_data_api": ">=1.6.0"
    }
}

class Config(Serializable):
    api_url: str = 'https://api.ndp.codewaves.cn'
    secret_token: str = 'ndp_pwd_114514'
    sync_interval: int = 30
    check_localhost: bool = True
    ip_record_interval: int = 30

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
            with open(path, 'w') as f:
                json.dump(default_data, f, indent=2)

    def load_data(self):
        try:
            with open(self._get_data_path('bans.json'), 'r') as f:
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
            with open(self._get_data_path('ips.json'), 'r') as f:
                self.ip_records = json.load(f)
        except Exception as e:
            self.server.logger.error(f'加载IP记录失败: {str(e)}')
            self.ip_records = {}

    def save_data(self):
        try:
            with open(self._get_data_path('bans.json'), 'w') as f:
                json.dump(self.bans, f, indent=2)
        except Exception as e:
            self.server.logger.error(f'保存封禁数据失败: {str(e)}')

    def save_ip_data(self):
        try:
            with open(self._get_data_path('ips.json'), 'w') as f:
                json.dump(self.ip_records, f, indent=2)
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
        self.ip_logger = server.get_plugin_instance('player_ip_logger')
        if self.ip_logger is None:
            server.logger.warning('缺少Player IP Logger,使用Minecraft Data API')
        
        self.register_commands()
        self.start_sync_timer()
        self.start_ip_record_timer()
        
        server.register_event_listener(
            'mcdr.player_joined', 
            lambda player, info, _: self.on_player_joined(player, info)
        )
        server.register_event_listener(
            'mcdr.player_left',
            lambda player, info, _: self.on_player_left(player)
        )

    def register_commands(self):
        cmd = Literal('!!ndp').requires(lambda src: src.has_permission(3))
        
        cmd.then(
            Literal('help').runs(self.cmd_show_help)
        ).then(
            Literal('ban').then(
                Text('player').then(
                    GreedyText('reason').runs(self._cmd_ban_player)
                )
            )
        ).then(
            Literal('pardon').then(
                Text('player').then(
                    GreedyText('reason').runs(self._cmd_pardon_player)
                )
            )
        ).then(
            Literal('sync').runs(self._cmd_sync_bans)
        ).then(
            Literal('reload').runs(self._cmd_reload_config)
        ).then(
            Literal('ip').then(
                Text('player').runs(self._cmd_show_ip)
            )
        ).then(
            Literal('status').runs(self._cmd_show_status)
        )
        
        self.server.register_command(cmd)

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
            f'§a同步间隔: {self.config.sync_interval}秒',
            f'§aIP记录方式: {"IP Logger" if self.ip_logger else "Minecraft Data API"}',
            '§a当前版本: v1.7.0'
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
                
                if self.ban_data.is_player_online(player):
                    self.kick_player(player, reason)
            except Exception as e:
                source.reply(f'§c[NDP]向云端服务器发送封禁请求时发生异常: {str(e)}')
        else:
            source.reply(f'§c[NDP]找不到玩家 {player} 的IP记录')

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
        except Exception as e:
            source.reply(f'§c[NDP]向云端服务器发送解封请求时发生异常: {str(e)}')

    def _cmd_sync_bans(self, source: CommandSource, ctx: CommandContext):
        self.sync_bans(source, show_message=True)

    def _cmd_reload_config(self, source: CommandSource, ctx: CommandContext):
        self.load_config()
        self.stop_sync_timer()
        self.stop_ip_record_timer()
        self.start_sync_timer()
        self.start_ip_record_timer()
        source.reply('§a[NDP]配置已重新加载')

    def _cmd_show_ip(self, source: CommandSource, ctx: CommandContext):
        player = ctx['player']
        if ip := self._get_player_ip(player):
            source.reply(f'§a[NDP]玩家 {player} 的IP: {ip}')
        else:
            source.reply(f'§c[NDP]找不到玩家 {player} 的IP记录')

    def _cmd_show_status(self, source: CommandSource, ctx: CommandContext):
        try:
            status = [
                '§6=== NDP封禁系统状态 ===',
                f'§aAPI地址: {self.config.api_url}',
                f'§a封禁IP数量: {len(self.ban_data.bans.get("ip_bans", {}))}',
                f'§a封禁玩家数量: {len(self.ban_data.bans.get("player_bans", {}))}',
                f'§a在线玩家数量: {len(self.ban_data.online_players)}',
                f'§a最后同步时间: {self.ban_data.bans.get("last_sync", "从未同步")}',
                f'§aIP记录方式: {"IP Logger" if self.ip_logger else "Minecraft Data API"}',
            ]
            source.reply('\n'.join(status))
        except Exception as e:
            self.server.logger.error(f'显示状态时出错: {str(e)}')
            source.reply('§c[NDP]获取状态信息时出错')

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
            self.server.logger.error(f'获取玩家 {player} IP时发生意外错误: {str(e)}')
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
            self.sync_bans()
        except Exception as e:
            self.server.logger.error(f'同步任务出错: {str(e)}')
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
            self.server.logger.error(f'记录IP任务出错: {str(e)}')
        finally:
            self.__schedule_next_ip_record()

    def stop_ip_record_timer(self):
        if self.__ip_record_timer is not None:
            self.__ip_record_timer.cancel()
            self.__ip_record_timer = None

    def record_all_online_ips(self):
        for player in list(self.ban_data.online_players):
            if ip := self._get_player_ip(player):
                self.ban_data.record_ip(player, ip)

    def on_player_joined(self, player: str, info: dict):
        self.ban_data.update_online_status(player, True)
    
        if ip := self._get_player_ip(player):
            self.ban_data.record_ip(player, ip)
        
            if ip == '127.0.0.1' and self.config.check_localhost:
                self.server.logger.warning('§e你似乎正在使用frp,请打开proxy protocol[代理端]选项,否则可能出现严重问题')
        
            try:
                response = requests.get(
                    f'{self.config.api_url}/check_ban',
                    params={
                        'username': player,
                        'ip': ip
                    },
                    headers={'Authorization': f'Bearer {self.config.secret_token}'},
                    timeout=5
                )
                response.raise_for_status()
                data = response.json()
                
                if data.get('action') == 'kick':
                    reason = data.get('cause', '你已被封禁')
                    ban_type = data.get('info', {}).get('ban_type', '未知类型')
                    
                    if ban_type == 'ip':
                        related_players = data.get('info', {}).get('related_players', [])
                        if related_players:
                            reason += f" (关联玩家: {', '.join(related_players)})"
                    elif ban_type == 'player':
                        related_ips = data.get('info', {}).get('related_ips', [])
                        if related_ips:
                            reason += f" (关联IP: {', '.join(related_ips)})"
                    
                    self.kick_player(player, reason)
                    self.server.say(f'§c[NDP]检测到封禁玩家: {player} ({ban_type}封禁)')
                    return
            
            except Exception as e:
                self.server.logger.warning(f'无法连接到NDP服务器 {str(e)},将使用本地数据检查')
        
            if self.ban_data.is_ip_banned(ip):
                self.kick_player(player, '§c[NDP]你的IP已被封禁')
            elif self.ban_data.is_player_banned(player):
                self.kick_player(player, '§c[NDP]你已被封禁')

    def on_player_left(self, player: str):
        self.ban_data.update_online_status(player, False)

    def sync_bans(self, source: Optional[CommandSource] = None, show_message: bool = True):
        try:
            response = requests.get(
                f'{self.config.api_url}/bans',
                headers={'Authorization': f'Bearer {self.config.secret_token}'},
                timeout=10
            )
            response.raise_for_status()
        
            data = response.json()
            self.ban_data.bans = {
                'ip_bans': data.get('ip_bans', {}),
                'player_bans': data.get('player_bans', {}),
                'last_sync': data.get('timestamp')
            }
            self.ban_data.save_data()
        
            self.check_online_players()
        
            msg = '§a[NDP]封禁列表同步完成'
            if show_message and source:
                source.reply(msg)
            self.server.logger.info(msg)
        except Exception as e:
            error_msg = f'同步封禁列表失败: {str(e)}'
            self.server.logger.error(error_msg)
            if show_message and source:
                source.reply(f'§c[NDP]{error_msg}')

    def check_online_players(self):
        kicked_players = []
    
        for player in list(self.ban_data.online_players):
            ip = self._get_player_ip(player)
        
            try:
                response = requests.get(
                    f'{self.config.api_url}/check_ban',
                    params={
                        'username': player,
                        'ip': ip or ""
                    },
                    headers={'Authorization': f'Bearer {self.config.secret_token}'},
                    timeout=5
                )
                response.raise_for_status()
                data = response.json()
                
                if data.get('action') == 'kick':
                    reason = data.get('cause', '你已被封禁')
                    ban_type = data.get('info', {}).get('ban_type', '未知类型')
                    
                    if ban_type == 'ip':
                        related_players = data.get('info', {}).get('related_players', [])
                        if related_players:
                            reason += f" (关联玩家: {', '.join(related_players)})"
                    elif ban_type == 'player':
                        related_ips = data.get('info', {}).get('related_ips', [])
                        if related_ips:
                            reason += f" (关联IP: {', '.join(related_ips)})"
                    
                    self.kick_player(player, reason)
                    kicked_players.append(f'{player}({ban_type}封禁)')
                    continue
                    
            except Exception as e:
                self.server.logger.warning(f'在线检查失败: {str(e)}，将使用本地数据检查')
        
            if self.ban_data.is_player_banned(player):
                reason = self.ban_data.bans['player_bans'].get(player, '§c[NDP]你已被封禁')
                self.kick_player(player, reason)
                kicked_players.append(f'{player}(玩家名封禁)')
            elif ip and self.ban_data.is_ip_banned(ip):
                reason = self.ban_data.bans['ip_bans'].get(ip, '§c[NDP]你已被封禁')
                self.kick_player(player, reason)
                kicked_players.append(f'{player}(IP封禁: {ip})')
    
        if kicked_players:
            msg = f'§c[NDP]检测到封禁玩家: {", ".join(kicked_players)}'
            self.server.logger.info(msg)
            self.server.say(msg)

    def kick_player(self, player: str, reason: str):
        self.server.execute(f'kick {player} {reason}')
        self.server.logger.info(f'已踢出玩家 {player}: {reason}')

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
