#!/usr/bin/env python3
"""
CF-Clearance-Server - API server để lấy Cloudflare clearance cookies (cf_clearance)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
import uuid
from typing import Dict, Optional, List, Any

from quart import Quart, jsonify, request, render_template_string
import zendriver
from selenium_authenticated_proxy import SeleniumAuthenticatedProxy
from zendriver.cdp.network import Cookie
import latest_user_agents
import random
import socket
from datetime import datetime

# Thiết lập logging
COLORS = {
    'MAGENTA': '\033[35m',
    'BLUE': '\033[34m',
    'GREEN': '\033[32m',
    'YELLOW': '\033[33m',
    'RED': '\033[31m',
    'RESET': '\033[0m',
}

class CustomLogger(logging.Logger):
    @staticmethod
    def format_message(level, color, message):
        timestamp = time.strftime('%H:%M:%S')
        return f"[{timestamp}] [{COLORS.get(color)}{level}{COLORS.get('RESET')}] -> {message}"

    def debug(self, message, *args, **kwargs):
        super().debug(self.format_message('DEBUG', 'MAGENTA', message), *args, **kwargs)

    def info(self, message, *args, **kwargs):
        super().info(self.format_message('INFO', 'BLUE', message), *args, **kwargs)

    def success(self, message, *args, **kwargs):
        super().info(self.format_message('SUCCESS', 'GREEN', message), *args, **kwargs)

    def warning(self, message, *args, **kwargs):
        super().warning(self.format_message('WARNING', 'YELLOW', message), *args, **kwargs)

    def error(self, message, *args, **kwargs):
        super().error(self.format_message('ERROR', 'RED', message), *args, **kwargs)

logging.setLoggerClass(CustomLogger)
logger = logging.getLogger("CF-Clearance-Server")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)

def get_chrome_user_agent() -> str:
    """
    Lấy ngẫu nhiên một User-Agent Chrome cập nhật.
    """
    chrome_user_agents = [
        user_agent
        for user_agent in latest_user_agents.get_latest_user_agents()
        if "Chrome" in user_agent
    ]
    return random.choice(chrome_user_agents)

class CloudflareSolver:
    """
    Giải quyết Cloudflare challenge và lấy cf_clearance cookie.
    """
    def __init__(
        self,
        *,
        user_agent: Optional[str],
        timeout: float,
        http2: bool = True,
        http3: bool = True,
        headless: bool = True,
        proxy: Optional[str] = None,
    ) -> None:
        """Khởi tạo Cloudflare solver."""
        config = zendriver.Config(headless=headless)

        if user_agent is not None:
            config.add_argument(f"--user-agent={user_agent}")

        if not http2:
            config.add_argument("--disable-http2")

        if not http3:
            config.add_argument("--disable-quic")

        # Thiết lập proxy
        auth_proxy = SeleniumAuthenticatedProxy(proxy)
        auth_proxy.enrich_chrome_options(config)

        self.driver = zendriver.Browser(config)
        self._timeout = timeout
        self.user_agent = user_agent

    async def __aenter__(self) -> CloudflareSolver:
        """Context manager entry."""
        await self.driver.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        """Context manager exit."""
        await self.driver.stop()

    @staticmethod
    def _format_cookies(cookies: List[Cookie]) -> List[Dict[str, Any]]:
        """Format cookies thành JSON."""
        return [cookie.to_json() for cookie in cookies]

    @staticmethod
    def extract_clearance_cookie(
        cookies: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Trích xuất cf_clearance cookie từ danh sách cookies."""
        for cookie in cookies:
            if cookie["name"] == "cf_clearance":
                return cookie
        return None

    async def get_user_agent(self) -> str:
        """Lấy user agent hiện tại."""
        return await self.driver.main_tab.evaluate("navigator.userAgent")

    async def get_cookies(self) -> List[Dict[str, Any]]:
        """Lấy tất cả cookies từ trang hiện tại."""
        return self._format_cookies(await self.driver.cookies.get_all())

    async def solve_cloudflare(self, url: str) -> Dict[str, Any]:
        """
        Giải quyết Cloudflare challenge và trả về kết quả.
        """
        start_time = time.time()
        logger.info(f"Truy cập {url}...")
        
        try:
            # Truy cập URL
            await self.driver.get(url)
            
            # Kiểm tra cf_clearance cookie
            all_cookies = await self.get_cookies()
            clearance_cookie = self.extract_clearance_cookie(all_cookies)
            
            if clearance_cookie is None:
                # Kiểm tra nếu có thử thách Cloudflare
                logger.info("Đang tìm và giải quyết Cloudflare challenge...")
                
                # Đợi tối đa timeout giây để Cloudflare challenge tự động được giải quyết
                start_wait = time.time()
                while time.time() - start_wait < self._timeout:
                    # Kiểm tra lại cookies sau mỗi 1 giây
                    await asyncio.sleep(1)
                    all_cookies = await self.get_cookies()
                    clearance_cookie = self.extract_clearance_cookie(all_cookies)
                    if clearance_cookie:
                        break
                
                # Nếu vẫn không có cookie, thử tương tác với các thành phần
                if not clearance_cookie:
                    logger.info("Tự động tương tác với các thành phần của trang...")
                    try:
                        # Tìm và nhấp vào các nút có thể là một phần của thử thách
                        buttons = await self.driver.main_tab.find_all("button")
                        for button in buttons:
                            try:
                                await button.mouse_click()
                                await asyncio.sleep(2)
                            except:
                                pass
                        
                        # Tìm và nhấp vào các checkbox
                        checkboxes = await self.driver.main_tab.find_all("input[type=checkbox]")
                        for checkbox in checkboxes:
                            try:
                                await checkbox.mouse_click()
                                await asyncio.sleep(2)
                            except:
                                pass
                        
                        # Kiểm tra lại cookies
                        all_cookies = await self.get_cookies()
                        clearance_cookie = self.extract_clearance_cookie(all_cookies)
                    except Exception as e:
                        logger.warning(f"Lỗi khi tương tác với trang: {str(e)}")
            
            # Lấy user agent thực tế
            current_user_agent = await self.get_user_agent()
            
            elapsed_time = round(time.time() - start_time, 3)
            
            if clearance_cookie:
                logger.success(f"Đã lấy được cf_clearance cookie trong {elapsed_time} giây")
                return {
                    "status": "success",
                    "elapsed_time": elapsed_time,
                    "cf_clearance": clearance_cookie["value"],
                    "user_agent": current_user_agent,
                    "all_cookies": all_cookies
                }
            else:
                logger.error(f"Không lấy được cf_clearance cookie sau {elapsed_time} giây")
                return {
                    "status": "error",
                    "reason": "Failed to retrieve cf_clearance cookie",
                    "elapsed_time": elapsed_time
                }
                
        except Exception as e:
            elapsed_time = round(time.time() - start_time, 3)
            logger.error(f"Lỗi khi giải quyết Cloudflare challenge: {str(e)}")
            return {
                "status": "error",
                "reason": str(e),
                "elapsed_time": elapsed_time
            }

# Khởi tạo API server
app = Quart(__name__)

# Biến lưu trữ
task_results = {}
active_solvers = {}
max_concurrent_tasks = 10
server_info = {
    "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    "version": "1.0.0",
    "name": "CF-Clearance-Server"
}

async def cleanup_tasks():
    """
    Xóa các task cũ để tránh rò rỉ bộ nhớ.
    """
    while True:
        await asyncio.sleep(3600)  # Chạy mỗi giờ
        now = time.time()
        keys_to_delete = []
        
        for task_id, result in task_results.items():
            if isinstance(result, dict) and result.get("timestamp", 0) < now - 86400:  # 24 giờ
                keys_to_delete.append(task_id)
        
        for task_id in keys_to_delete:
            if task_id in task_results:
                del task_results[task_id]
        
        logger.info(f"Đã xóa {len(keys_to_delete)} task cũ")

@app.before_serving
async def before_serving():
    """
    Chạy trước khi server bắt đầu phục vụ.
    """
    asyncio.create_task(cleanup_tasks())
    logger.info(f"CF-Clearance-Server v{server_info['version']} đã khởi động")

@app.after_serving
async def after_serving():
    """
    Dọn dẹp sau khi server dừng.
    """
    for solver in active_solvers.values():
        try:
            await solver.driver.stop()
        except:
            pass
    logger.info("CF-Clearance-Server đã dừng")

async def solve_cloudflare_task(task_id: str, url: str, user_agent: Optional[str], proxy: Optional[str], timeout: int = 60):
    """
    Xử lý task giải quyết Cloudflare challenge.
    """
    start_time = time.time()
    
    if not user_agent:
        user_agent = get_chrome_user_agent()
        logger.info(f"Sử dụng user agent ngẫu nhiên: {user_agent}")
    
    try:
        task_results[task_id] = {"status": "processing", "timestamp": time.time()}
        
        if proxy:
            logger.info(f"Sử dụng proxy: {proxy}")
        
        # Tạo solver
        solver = CloudflareSolver(
            user_agent=user_agent,
            timeout=timeout,
            headless=True,
            proxy=proxy
        )
        
        active_solvers[task_id] = solver
        
        async with solver:
            # Giải quyết challenge
            result = await solver.solve_cloudflare(url)
            result["timestamp"] = time.time()
            
            # Lưu kết quả
            task_results[task_id] = result
    
    except Exception as e:
        logger.error(f"Lỗi khi xử lý task {task_id}: {str(e)}")
        task_results[task_id] = {
            "status": "error",
            "reason": str(e),
            "elapsed_time": round(time.time() - start_time, 3),
            "timestamp": time.time()
        }
    finally:
        # Đảm bảo xóa solver khỏi danh sách active
        if task_id in active_solvers:
            del active_solvers[task_id]

@app.route('/')
async def index():
    """
    Trang chủ API.
    """
    hostname = socket.gethostname()
    try:
        ip_address = socket.gethostbyname(hostname)
    except:
        ip_address = "127.0.0.1"
    
    template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>CF-Clearance-Server</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-900 text-gray-200 min-h-screen flex items-center justify-center">
        <div class="container mx-auto max-w-4xl p-6">
            <div class="bg-gray-800 rounded-lg shadow-lg border border-blue-500 overflow-hidden">
                <div class="p-6 border-b border-gray-700">
                    <div class="flex items-center justify-between">
                        <h1 class="text-3xl font-bold text-blue-500">CF-Clearance-Server</h1>
                        <span class="px-3 py-1 bg-green-800 text-green-100 rounded-full text-sm">Online</span>
                    </div>
                    <p class="mt-2 text-gray-400">Giải quyết Cloudflare challenges và lấy cf_clearance cookies</p>
                </div>
                
                <div class="p-6 border-b border-gray-700">
                    <h2 class="text-xl font-semibold text-blue-400 mb-4">Thông tin Server</h2>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="bg-gray-700 p-4 rounded-md">
                            <span class="text-gray-400">Hostname:</span>
                            <span class="ml-2">{{ hostname }}</span>
                        </div>
                        <div class="bg-gray-700 p-4 rounded-md">
                            <span class="text-gray-400">IP Address:</span>
                            <span class="ml-2">{{ ip_address }}</span>
                        </div>
                        <div class="bg-gray-700 p-4 rounded-md">
                            <span class="text-gray-400">Phiên bản:</span>
                            <span class="ml-2">{{ version }}</span>
                        </div>
                        <div class="bg-gray-700 p-4 rounded-md">
                            <span class="text-gray-400">Thời gian khởi động:</span>
                            <span class="ml-2">{{ start_time }}</span>
                        </div>
                        <div class="bg-gray-700 p-4 rounded-md">
                            <span class="text-gray-400">Active Tasks:</span>
                            <span class="ml-2">{{ active_tasks }}/{{ max_tasks }}</span>
                        </div>
                        <div class="bg-gray-700 p-4 rounded-md">
                            <span class="text-gray-400">Tasks đã xử lý:</span>
                            <span class="ml-2">{{ total_tasks }}</span>
                        </div>
                    </div>
                </div>
                
                <div class="p-6 border-b border-gray-700">
                    <h2 class="text-xl font-semibold text-blue-400 mb-4">API Endpoints</h2>
                    
                    <div class="bg-gray-700 p-4 rounded-md mb-4">
                        <h3 class="font-semibold text-blue-300">1. Giải quyết Cloudflare Challenge</h3>
                        <code class="block mt-2 bg-gray-800 p-3 rounded text-green-400 overflow-x-auto">
                            GET /solve?url=https://example.com&proxy=http://user:pass@proxy.com:port&user_agent=Mozilla/5.0...
                        </code>
                        <div class="mt-2 text-sm">
                            <div><span class="text-gray-400">url</span> - URL của trang web có Cloudflare protection (bắt buộc)</div>
                            <div><span class="text-gray-400">proxy</span> - Proxy URL (tùy chọn, nhưng khuyến nghị)</div>
                            <div><span class="text-gray-400">user_agent</span> - User Agent string (tùy chọn)</div>
                            <div><span class="text-gray-400">timeout</span> - Thời gian chờ tối đa (giây, mặc định: 60)</div>
                        </div>
                    </div>
                    
                    <div class="bg-gray-700 p-4 rounded-md mb-4">
                        <h3 class="font-semibold text-blue-300">2. Lấy kết quả</h3>
                        <code class="block mt-2 bg-gray-800 p-3 rounded text-green-400 overflow-x-auto">
                            GET /result?id=task_id
                        </code>
                        <div class="mt-2 text-sm">
                            <div><span class="text-gray-400">id</span> - Task ID nhận được từ /solve</div>
                        </div>
                    </div>
                    
                    <div class="bg-gray-700 p-4 rounded-md">
                        <h3 class="font-semibold text-blue-300">3. Kiểm tra trạng thái server</h3>
                        <code class="block mt-2 bg-gray-800 p-3 rounded text-green-400 overflow-x-auto">
                            GET /status
                        </code>
                    </div>
                </div>
                
                <div class="p-6">
                    <h2 class="text-xl font-semibold text-blue-400 mb-4">Lưu ý quan trọng</h2>
                    <div class="bg-blue-900 border-l-4 border-blue-500 p-4 rounded-md">
                        <p class="mb-2">Cookie cf_clearance chỉ hoạt động khi:</p>
                        <ul class="list-disc pl-6 space-y-1">
                            <li>Bạn sử dụng <strong>chính xác</strong> User-Agent đã được trả về</li>
                            <li>Bạn sử dụng proxy có IP trùng với IP đã sử dụng để lấy cookie</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    
    return await render_template_string(
        template,
        hostname=hostname,
        ip_address=ip_address,
        version=server_info["version"],
        start_time=server_info["start_time"],
        active_tasks=len(active_solvers),
        max_tasks=max_concurrent_tasks,
        total_tasks=len(task_results)
    )

@app.route('/solve')
async def solve():
    """
    Endpoint để bắt đầu giải quyết Cloudflare challenge.
    """
    url = request.args.get('url')
    proxy = request.args.get('proxy')
    user_agent = request.args.get('user_agent')
    timeout = request.args.get('timeout', 60, type=int)
    
    # Kiểm tra tham số
    if not url:
        return jsonify({
            "status": "error",
            "error": "URL parameter is required"
        }), 400
    
    # Kiểm tra định dạng proxy
    if proxy and not (
        proxy.startswith('http://') or 
        proxy.startswith('https://') or 
        proxy.startswith('socks4://') or 
        proxy.startswith('socks5://')
    ):
        return jsonify({
            "status": "error",
            "error": "Invalid proxy format. Must start with http://, https://, socks4:// or socks5://"
        }), 400
    
    # Giới hạn timeout
    if timeout > 120:
        timeout = 120
    
    # Kiểm tra số lượng task đang chạy
    if len(active_solvers) >= max_concurrent_tasks:
        return jsonify({
            "status": "error",
            "error": f"Server đang xử lý tối đa số lượng task ({max_concurrent_tasks}). Vui lòng thử lại sau."
        }), 429
    

    # Tạo task ID
    task_id = str(uuid.uuid4())
    
    # Bắt đầu task
    asyncio.create_task(solve_cloudflare_task(
        task_id=task_id,
        url=url,
        user_agent=user_agent,
        proxy=proxy,
        timeout=timeout
    ))
    
    logger.info(f"Đã tạo task {task_id} cho URL: {url}")
    
    return jsonify({
        "status": "success",
        "task_id": task_id,
        "message": f"Task đã được tạo, kết quả sẽ sẵn sàng trong tối đa {timeout} giây"
    }), 202

@app.route('/result')
async def get_result():
    """
    Lấy kết quả của một task.
    """
    task_id = request.args.get('id')
    
    if not task_id:
        return jsonify({
            "status": "error",
            "error": "id parameter is required"
        }), 400
    
    if task_id not in task_results:
        return jsonify({
            "status": "error",
            "error": "Task ID không tồn tại"
        }), 404
    
    result = task_results[task_id]
    
    if result.get("status") == "processing":
        return jsonify({
            "status": "processing",
            "message": "Task đang được xử lý"
        }), 202
    
    return jsonify(result), 200

@app.route('/status')
async def get_status():
    """
    Lấy trạng thái của server.
    """
    status_counts = {
        "processing": 0,
        "success": 0,
        "error": 0
    }
    
    for result in task_results.values():
        if isinstance(result, dict):
            status = result.get("status")
            if status in status_counts:
                status_counts[status] += 1
    
    return jsonify({
        "status": "online",
        "name": server_info["name"],
        "version": server_info["version"],
        "start_time": server_info["start_time"],
        "current_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "active_tasks": len(active_solvers),
        "max_concurrent_tasks": max_concurrent_tasks,
        "tasks_stats": status_counts,
        "total_tasks": len(task_results)
    }), 200

def parse_args():
    """
    Phân tích tham số dòng lệnh.
    """
    parser = argparse.ArgumentParser(description="CF-Clearance-Server - Giải quyết Cloudflare challenges và lấy cf_clearance cookies")
    
    parser.add_argument('--host', default='127.0.0.1', help='Host địa chỉ để lắng nghe (mặc định: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000, help='Cổng để lắng nghe (mặc định: 5000)')
    parser.add_argument('--max-tasks', type=int, default=10, help='Số task tối đa xử lý đồng thời (mặc định: 10)')
    parser.add_argument('--log-level', default='info', choices=['debug', 'info', 'warning', 'error'], 
                        help='Cấp độ ghi log (mặc định: info)')
    
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    
    # Thiết lập log level
    log_levels = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR
    }
    logger.setLevel(log_levels[args.log_level])
    
    # Thiết lập max_concurrent_tasks
    max_concurrent_tasks = args.max_tasks
    
    # Khởi động server
    import hypercorn.asyncio
    import hypercorn.config
    
    config = hypercorn.config.Config()
    config.bind = [f"{args.host}:{args.port}"]
    
    logger.info(f"Khởi động CF-Clearance-Server trên {args.host}:{args.port}")
    asyncio.run(hypercorn.asyncio.serve(app, config))