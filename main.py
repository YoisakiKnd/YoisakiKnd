
import sys
import os
import threading
import time
import ctypes
import ctypes.wintypes
import psutil
import json
from flask import Flask, jsonify, Response
from io import BytesIO
from PIL import Image, ImageFilter
import mss
import toml

# 配置文件统一为 TOML
CONFIG_FILE = "peek_config.toml"
DEFAULT_CONFIG = {
    'settings': {'blur': 5, 'blur_enabled': True, 'privacy_mode': False},
    'blacklist': []
}
settings = DEFAULT_CONFIG['settings'].copy()
blacklist = list(DEFAULT_CONFIG['blacklist'])

def migrate_old_config():
    """自动迁移旧json配置到TOML"""
    migrated = False
    settings_file = "settings.json"
    blacklist_file = "blacklist.json"
    config = DEFAULT_CONFIG.copy()
    # 迁移settings.json
    if os.path.exists(settings_file):
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                config['settings'] = json.load(f)
            os.remove(settings_file)
            migrated = True
        except Exception:
            pass
    # 迁移blacklist.json
    if os.path.exists(blacklist_file):
        try:
            with open(blacklist_file, "r", encoding="utf-8") as f:
                config['blacklist'] = json.load(f)
            os.remove(blacklist_file)
            migrated = True
        except Exception:
            pass
    if migrated:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            toml.dump(config, f)

def load_config():
    global settings, blacklist
    if not os.path.exists(CONFIG_FILE):
        # 写入默认配置
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            toml.dump(DEFAULT_CONFIG, f)
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            config = toml.load(f)
        settings = config.get('settings', DEFAULT_CONFIG['settings']).copy()
        blacklist[:] = config.get('blacklist', DEFAULT_CONFIG['blacklist'])
    except Exception:
        settings = DEFAULT_CONFIG['settings'].copy()
        blacklist.clear()

def save_config():
    config = {
        'settings': settings,
        'blacklist': blacklist
    }
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        toml.dump(config, f)

def get_foreground_window_handle():
    return ctypes.windll.user32.GetForegroundWindow()

def get_window_title():
    hwnd = get_foreground_window_handle()
    length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
    buff = ctypes.create_unicode_buffer(length + 1)
    ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
    return buff.value

def get_foreground_app():
    hwnd = get_foreground_window_handle()
    pid = ctypes.c_ulong()
    ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    for proc in psutil.process_iter(['pid', 'name']):
        if proc.info['pid'] == pid.value:
            return proc.info['name']
    return None

def is_blacklisted_running():
    running = set(p.info['name'] for p in psutil.process_iter(['name']) if p.info['name'])
    blist = set(os.path.basename(p).lower() for p in blacklist)
    blist |= set(os.path.splitext(os.path.basename(p))[0] for p in blacklist)
    for proc in running:
        pname = proc.lower()
        pname_noext = os.path.splitext(pname)[0]
        if pname in blist or pname_noext in blist:
            return True
    return False

def get_running_processes():
    processes = set()
    for proc in psutil.process_iter(['name', 'username']):
        name = proc.info['name']
        username = proc.info.get('username', '')
        # 过滤掉常见系统进程（用户名为SYSTEM、LOCAL SERVICE、NETWORK SERVICE等，或无用户名）
        if not name:
            continue
        uname = str(username).lower()
        if uname in ('', 'system', 'local service', 'network service', 'services', 'dwm-1', 'umfd-0', 'umfd-1'):
            continue
        # 进一步过滤常见的系统进程名
        sys_names = {'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe', 'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe', 'fontdrvhost.exe', 'winlogon.exe', 'dwm.exe', 'spoolsv.exe', 'sihost.exe', 'explorer.exe', 'taskhostw.exe', 'ctfmon.exe', 'searchui.exe', 'startmenuexperiencehost.exe', 'runtimebroker.exe', 'securityhealthservice.exe', 'wudfhost.exe', 'backgroundtaskhost.exe', 'systemsettings.exe', 'searchapp.exe', 'applicationframehost.exe', 'textinputhost.exe', 'audiodg.exe', 'conhost.exe', 'msedgewebview2.exe'}
        if name.lower() in sys_names:
            continue
        processes.add(name)
    return sorted(processes)

def get_battery_status():
    try:
        battery = psutil.sensors_battery()
        if battery is None:
            return None, None
        percent = battery.percent
        charging = battery.power_plugged
        return percent, charging
    except Exception:
        return None, None

def get_cursor_pos():
    pt = ctypes.wintypes.POINT()
    ctypes.windll.user32.GetCursorPos(ctypes.byref(pt))
    return (pt.x, pt.y)

def get_mouse_idle_time(threshold=10):
    last_pos = get_cursor_pos()
    last_time = time.time()
    while True:
        time.sleep(0.5)
        pos = get_cursor_pos()
        if (abs(pos[0] - last_pos[0]) > threshold or abs(pos[1] - last_pos[1]) > threshold):
            last_pos = pos
            last_time = time.time()
        yield time.time() - last_time

def get_fullscreen_screenshot():
    with mss.mss() as sct:
        monitor = sct.monitors[0]
        screenshot = sct.grab(monitor)
        img = Image.frombytes('RGB', (screenshot.width, screenshot.height), screenshot.rgb)
        return img

def get_fullscreen_screenshot_with_blur(radius=2):
    img = get_fullscreen_screenshot()
    if radius > 0:
        img = img.filter(ImageFilter.GaussianBlur(radius=radius))
    return img

def blur_blacklisted_window_only(full_img, blur_radius):
    try:
        # 构建黑名单名集合
        blist = set()
        for p in blacklist:
            base = os.path.basename(p).lower()
            blist.add(base)
            blist.add(os.path.splitext(base)[0])
        # 获取所有窗口Z序，从顶到底，找到第一个黑名单窗口并模糊
        EnumWindows = ctypes.windll.user32.EnumWindows
        EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.wintypes.HWND, ctypes.wintypes.LPARAM)
        GetWindowThreadProcessId = ctypes.windll.user32.GetWindowThreadProcessId
        GetWindowRect = ctypes.windll.user32.GetWindowRect
        IsWindowVisible = ctypes.windll.user32.IsWindowVisible
        rect = ctypes.wintypes.RECT()
        screen_width, screen_height = full_img.size
        hwnds = []
        def collect_hwnds(hwnd, lParam):
            if IsWindowVisible(hwnd):
                hwnds.append(hwnd)
            return True
        EnumWindows(EnumWindowsProc(collect_hwnds), 0)
        # 从顶到底遍历，找到第一个黑名单窗口，判断其是否被遮挡
        target_hwnd = None
        target_rect = None
        for hwnd in hwnds:
            pid = ctypes.c_ulong()
            GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            try:
                proc = psutil.Process(pid.value)
                pname = proc.name().lower()
                pname_noext = os.path.splitext(pname)[0]
                if pname in blist or pname_noext in blist:
                    if GetWindowRect(hwnd, ctypes.byref(rect)):
                        left, top, right, bottom = rect.left, rect.top, rect.right, rect.bottom
                        inter_left = max(0, left)
                        inter_top = max(0, top)
                        inter_right = min(screen_width, right)
                        inter_bottom = min(screen_height, bottom)
                        if inter_right > inter_left and inter_bottom > inter_top:
                            target_hwnd = hwnd
                            target_rect = (inter_left, inter_top, inter_right, inter_bottom)
                            break
            except Exception:
                pass
        if target_hwnd is None or target_rect is None:
            return full_img
        # 计算所有上层窗口对目标窗口的遮挡区域
        idx = hwnds.index(target_hwnd)
        cover_rects = []
        for hwnd in hwnds[:idx]:
            if hwnd == target_hwnd:
                continue
            if not IsWindowVisible(hwnd):
                continue
            if GetWindowRect(hwnd, ctypes.byref(rect)):
                l, t, r, b = rect.left, rect.top, rect.right, rect.bottom
                # 只收集与目标窗口有交集的遮挡区域
                x1 = max(target_rect[0], l)
                y1 = max(target_rect[1], t)
                x2 = min(target_rect[2], r)
                y2 = min(target_rect[3], b)
                if x2 > x1 and y2 > y1:
                    cover_rects.append((x1, y1, x2, y2))

        # 区域减法：从target_rect中减去所有cover_rects，得到未被遮挡的区域
        def subtract_rects(base_rect, sub_rects):
            # base_rect: (l, t, r, b)
            # sub_rects: list of (l, t, r, b)
            result = [base_rect]
            for sx1, sy1, sx2, sy2 in sub_rects:
                new_result = []
                for rx1, ry1, rx2, ry2 in result:
                    # 计算交集
                    ix1 = max(rx1, sx1)
                    iy1 = max(ry1, sy1)
                    ix2 = min(rx2, sx2)
                    iy2 = min(ry2, sy2)
                    if ix2 <= ix1 or iy2 <= iy1:
                        # 无交集，保留原区域
                        new_result.append((rx1, ry1, rx2, ry2))
                    else:
                        # 有交集，分割为最多4个矩形
                        # 上
                        if ry1 < iy1:
                            new_result.append((rx1, ry1, rx2, iy1))
                        # 下
                        if iy2 < ry2:
                            new_result.append((rx1, iy2, rx2, ry2))
                        # 左
                        if rx1 < ix1:
                            new_result.append((rx1, iy1, ix1, iy2))
                        # 右
                        if ix2 < rx2:
                            new_result.append((ix2, iy1, rx2, iy2))
                result = new_result
            # 过滤掉无效区域
            return [r for r in result if r[2] > r[0] and r[3] > r[1]]

        visible_rects = subtract_rects(target_rect, cover_rects)
        # 只对未被遮挡的区域模糊
        for box in visible_rects:
            cropped = full_img.crop(box)
            blurred = cropped.filter(ImageFilter.GaussianBlur(radius=blur_radius))
            full_img.paste(blurred, box)
        return full_img
    except Exception as e:
        print(f"局部模糊失败: {e}")
        return full_img

def get_media_info():
    try:
        import asyncio
        import winrt.windows.media.control as media
        async def _get():
            try:
                manager = await media.GlobalSystemMediaTransportControlsSessionManager.request_async()
                session = manager.get_current_session()
                if not session:
                    return False, '', '', ''
                info = session.get_playback_info()
                is_playing = info.playback_status == media.GlobalSystemMediaTransportControlsSessionPlaybackStatus.PLAYING
                props = await session.try_get_media_properties_async()
                title = props.title or '' if props else ''
                artist = props.artist or '' if props else ''
                album = props.album_title or '' if props else ''
                return is_playing, title, artist, album
            except Exception:
                return False, '', '', ''
        try:
            return asyncio.run(_get())
        except RuntimeError:
            import nest_asyncio
            nest_asyncio.apply()
            return asyncio.run(_get())
    except Exception:
        return False, '', '', ''

# Flask主程序
app = Flask(__name__)

# 合并所有状态信息到 /status
@app.route('/status')
def status_api():
    load_config()
    idle_gen = get_mouse_idle_time()
    idle_time = next(idle_gen)
    is_playing, title, artist, album = get_media_info()
    battery_percent, charging = get_battery_status()
    return jsonify({
        'window_title': get_window_title(),
        'foreground_app': get_foreground_app(),
        'battery_percent': battery_percent,
        'charging': charging,
        'mouse_idle_seconds': int(idle_time),
        'media_playing': is_playing,
        'media_title': title,
        'media_artist': artist,
        'media_album': album,
        'settings': settings,
        'blacklist': blacklist,
        'running_processes': get_running_processes()
    })

@app.route('/screenshot')
def capture_screen():
    load_config()
    blur = settings.get('blur', 0)
    blur_enabled = settings.get('blur_enabled', True)
    privacy_mode = settings.get('privacy_mode', False)
    screenshot = None
    in_blacklist = is_blacklisted_running()
    apply_blur = blur_enabled and blur > 0
    if privacy_mode:
        return Response("隐私模式下不返回截图", status=403)
    else:
        if apply_blur:
            screenshot = get_fullscreen_screenshot_with_blur(blur)
        else:
            screenshot = get_fullscreen_screenshot()
            if in_blacklist:
                screenshot = blur_blacklisted_window_only(screenshot, blur)
    if screenshot:
        img_io = BytesIO()
        screenshot.save(img_io, format='JPEG', quality=50)
        img_io.seek(0)
        return Response(img_io, mimetype='image/jpeg')
    else:
        return Response("Failed to capture screen", status=500)

def main():
    migrate_old_config()
    load_config()
    print("Flask已启动，访问 http://127.0.0.1:1919/local_status 可获取本地状态。\n访问 http://127.0.0.1:1919/settings 可设置。Ctrl+C退出。")
    app.run(host='0.0.0.0', port=1919, debug=False, use_reloader=False)
# --- Flask设置界面 ---
from flask import render_template_string, request, redirect


# 美化并支持进程选择的HTML模板
SETTINGS_HTML = '''
<!DOCTYPE html>
<html lang="zh-cn">
<head>
    <meta charset="UTF-8">
    <title>PEEK 设置</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { font-family: 'Segoe UI',sans-serif; margin: 30px; background: #f7f9fa; }
        .container { max-width: 520px; background: #fff; border-radius: 12px; box-shadow:0 2px 12px #0001; padding: 32px 28px 24px 28px; }
        h2 { font-weight: 700; margin-bottom: 24px; }
        .form-label { font-weight: 500; }
        .block { margin-bottom: 28px; }
        .blacklist-list { list-style: none; padding-left: 0; }
        .blacklist-list li { margin-bottom: 6px; background: #f1f3f6; border-radius: 6px; padding: 4px 10px; display: flex; align-items: center; }
        .blacklist-list button { margin-left: auto; }
        .proc-select { width: 100%; max-width: 320px; }
        .add-row { display: flex; gap: 8px; margin-top: 8px; }
        .save-btn { width: 100%; font-size: 1.1em; }
        .msg { color: #198754; font-weight: 500; margin-top: 10px; }
    </style>
</head>
<body>
<div class="container">
    <h2>PEEK 设置</h2>
    <form method="post">
        <div class="block">
            <label class="form-label">模糊强度:</label>
            <input type="range" name="blur" min="0" max="20" value="{{blur}}" oninput="blur_val.value=value">
            <output id="blur_val">{{blur}}</output>
        </div>
        <div class="block form-check form-switch">
            <input class="form-check-input" type="checkbox" name="blur_enabled" id="blur_enabled" {% if blur_enabled %}checked{% endif %}>
            <label class="form-check-label" for="blur_enabled">启用模糊</label>
        </div>
        <div class="block form-check form-switch">
            <input class="form-check-input" type="checkbox" name="privacy_mode" id="privacy_mode" {% if privacy_mode %}checked{% endif %}>
            <label class="form-check-label" for="privacy_mode">隐私模式</label>
        </div>
        <div class="block">
            <label class="form-label">黑名单进程：</label>
            <ul class="blacklist-list">
            {% for item in blacklist %}
                <li>{{item}} <button class="btn btn-sm btn-danger" name="del" value="{{item}}">删除</button></li>
            {% endfor %}
            </ul>
            <div class="add-row">
                <input type="text" class="form-control" name="add" placeholder="手动输入进程名（如: WeChat.exe）">
                <button class="btn btn-primary" type="submit">添加</button>
            </div>
            <div class="add-row" style="margin-top:10px;">
                <select class="form-select proc-select" name="add_proc">
                    <option value="">从当前进程选择...</option>
                    {% for proc in running_processes %}
                        <option value="{{proc}}">{{proc}}</option>
                    {% endfor %}
                </select>
                <button class="btn btn-success" name="add_from_list" value="1">添加所选</button>
            </div>
        </div>
        <button class="btn btn-success save-btn" type="submit">保存设置</button>
    </form>
    {% if msg %}<div class="msg">{{msg}}</div>{% endif %}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
'''


@app.route('/settings', methods=['GET', 'POST'])
def settings_page():
    load_config()
    running_processes = get_running_processes()
    msg = ''
    if request.method == 'POST':
        # 删除黑名单
        if 'del' in request.form:
            val = request.form['del']
            if val in blacklist:
                blacklist.remove(val)
                save_config()
                msg = f"已删除: {val}"
        # 添加黑名单（手动输入）
        elif 'add' in request.form and request.form['add'].strip():
            val = request.form['add'].strip()
            if val and val not in blacklist:
                blacklist.append(val)
                save_config()
                msg = f"已添加: {val}"
        # 添加黑名单（从进程列表选择）
        elif 'add_from_list' in request.form and request.form.get('add_proc'):
            val = request.form.get('add_proc')
            if val and val not in blacklist:
                blacklist.append(val)
                save_config()
                msg = f"已添加: {val}"
        # 保存设置
        else:
            settings['blur'] = int(request.form.get('blur', settings.get('blur', 5)))
            settings['blur_enabled'] = 'blur_enabled' in request.form
            settings['privacy_mode'] = 'privacy_mode' in request.form
            save_config()
            msg = "设置已保存"
    # 重新加载以反映最新
    load_config()
    running_processes = get_running_processes()
    return render_template_string(
        SETTINGS_HTML,
        blur=settings.get('blur', 5),
        blur_enabled=settings.get('blur_enabled', True),
        privacy_mode=settings.get('privacy_mode', False),
        blacklist=blacklist,
        running_processes=running_processes,
        msg=msg
    )

if __name__ == '__main__':
    main()