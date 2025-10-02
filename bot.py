from aiohttp import (
    ClientResponseError,
    ClientSession,
    ClientTimeout,
    BasicAuth
)
from aiohttp_socks import ProxyConnector
from fake_useragent import FakeUserAgent
from http.cookies import SimpleCookie
from urllib.parse import quote
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import to_hex
from datetime import datetime, timezone
from colorama import *
import asyncio, time, json, re, os, pytz

wib = pytz.timezone('Asia/Jakarta')

class NitroGraph:
    def __init__(self) -> None:
        self.BASE_API = "https://community.nitrograph.com/api"
        self.AUTH_API = "https://api-web.nitrograph.com/api"
        self.REF_CODE = "XVQ07AO5" # U can change it with yours.
        self.BASE_HEADERS = {}
        self.AUTH_HEADERS = {}
        self.proxies = []
        self.proxy_index = 0
        self.account_proxies = {}
        self.access_tokens = {}
        self.refresh_tokens = {}
        self.wagmi_cookie = (
            'wagmi.recentConnectorId="io.metamask"; '
            'wagmi.store={"state":{"connections":{"__type":"Map","value":[["14ac6838b1f",{"accounts":["0x1d1aFC2d015963017bED1De13e4ed6c3d3ED1618"],"chainId":1,"connector":{"id":"io.metamask","name":"MetaMask","type":"injected","uid":"14ac6838b1f"}}]]},"chainId":1,"current":"14ac6838b1f"},"version":2}'
        )
        self.session_v1 = {}
        self.session_v4 = {}

    def clear_terminal(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def log(self, message):
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}{message}",
            flush=True
        )

    def welcome(self):
        print(
            f"""
        {Fore.GREEN + Style.BRIGHT}NitroGraph {Fore.BLUE + Style.BRIGHT}Auto BOT
            """
            f"""
        {Fore.GREEN + Style.BRIGHT}Rey? {Fore.YELLOW + Style.BRIGHT}<INI WATERMARK>
            """
        )

    def format_seconds(self, seconds):
        hours, remainder = divmod(seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{int(hours):02}:{int(minutes):02}:{int(seconds):02}"
    
    async def load_proxies(self):
        filename = "proxy.txt"
        try:
            if not os.path.exists(filename):
                self.log(f"{Fore.RED + Style.BRIGHT}File {filename} Not Found.{Style.RESET_ALL}")
                return
            with open(filename, 'r') as f:
                self.proxies = [line.strip() for line in f.read().splitlines() if line.strip()]
            
            if not self.proxies:
                self.log(f"{Fore.RED + Style.BRIGHT}No Proxies Found.{Style.RESET_ALL}")
                return

            self.log(
                f"{Fore.GREEN + Style.BRIGHT}Proxies Total  : {Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT}{len(self.proxies)}{Style.RESET_ALL}"
            )
        
        except Exception as e:
            self.log(f"{Fore.RED + Style.BRIGHT}Failed To Load Proxies: {e}{Style.RESET_ALL}")
            self.proxies = []

    def check_proxy_schemes(self, proxies):
        schemes = ["http://", "https://", "socks4://", "socks5://"]
        if any(proxies.startswith(scheme) for scheme in schemes):
            return proxies
        return f"http://{proxies}"

    def get_next_proxy_for_account(self, account):
        if account not in self.account_proxies:
            if not self.proxies:
                return None
            proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
            self.account_proxies[account] = proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return self.account_proxies[account]

    def rotate_proxy_for_account(self, account):
        if not self.proxies:
            return None
        proxy = self.check_proxy_schemes(self.proxies[self.proxy_index])
        self.account_proxies[account] = proxy
        self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy
    
    def build_proxy_config(self, proxy=None):
        if not proxy:
            return None, None, None

        if proxy.startswith("socks"):
            connector = ProxyConnector.from_url(proxy)
            return connector, None, None

        elif proxy.startswith("http"):
            match = re.match(r"http://(.*?):(.*?)@(.*)", proxy)
            if match:
                username, password, host_port = match.groups()
                clean_url = f"http://{host_port}"
                auth = BasicAuth(username, password)
                return None, clean_url, auth
            else:
                return None, proxy, None

        raise Exception("Unsupported Proxy Type.")
        
    def generate_address(self, account: str):
        try:
            account = Account.from_key(account)
            address = account.address

            return address
        except Exception as e:
            return None
    
    def generate_payload(self, account: str, address: str, nonce: str):
        try:
            timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            message = f"community.nitrograph.com wants you to sign in with your Ethereum account:\n{address}\n\nSign in to Nitrograph using your wallet\n\nURI: https://community.nitrograph.com\nVersion: 1\nChain ID: 200024\nNonce: {nonce}\nIssued At: {timestamp}"
            encoded_message = encode_defunct(text=message)
            signed_message = Account.sign_message(encoded_message, private_key=account)
            signature = to_hex(signed_message.signature)

            return {
                "message": message,
                "signature": signature
            }
        except Exception as e:
            raise Exception(f"Generate Req Payload Failed: {str(e)}")

    def mask_account(self, account):
        try:
            mask_account = account[:6] + '*' * 6 + account[-6:]
            return mask_account
        except Exception as e:
            return None

    def print_question(self):
        while True:
            try:
                print(f"{Fore.WHITE + Style.BRIGHT}1. Run With Proxy{Style.RESET_ALL}")
                print(f"{Fore.WHITE + Style.BRIGHT}2. Run Without Proxy{Style.RESET_ALL}")
                proxy_choice = int(input(f"{Fore.BLUE + Style.BRIGHT}Choose [1/2] -> {Style.RESET_ALL}").strip())

                if proxy_choice in [1, 2]:
                    proxy_type = (
                        "With" if proxy_choice == 1 else 
                        "Without"
                    )
                    print(f"{Fore.GREEN + Style.BRIGHT}Run {proxy_type} Proxy Selected.{Style.RESET_ALL}")
                    break
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Please enter either 1 or 2.{Style.RESET_ALL}")
            except ValueError:
                print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter a number (1 or 2).{Style.RESET_ALL}")

        rotate_proxy = False
        if proxy_choice == 1:
            while True:
                rotate_proxy = input(f"{Fore.BLUE + Style.BRIGHT}Rotate Invalid Proxy? [y/n] -> {Style.RESET_ALL}").strip()

                if rotate_proxy in ["y", "n"]:
                    rotate_proxy = rotate_proxy == "y"
                    break
                else:
                    print(f"{Fore.RED + Style.BRIGHT}Invalid input. Enter 'y' or 'n'.{Style.RESET_ALL}")

        return proxy_choice, rotate_proxy
    
    async def check_connection(self, proxy_url=None):
        connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
        try:
            async with ClientSession(connector=connector, timeout=ClientTimeout(total=30)) as session:
                async with session.get(url="https://api.ipify.org?format=json", proxy=proxy, proxy_auth=proxy_auth) as response:
                    response.raise_for_status()
                    return True
        except (Exception, ClientResponseError) as e:
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                f"{Fore.RED+Style.BRIGHT} Connection Not 200 OK {Style.RESET_ALL}"
                f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
            )
        
        return None
    
    async def auth_nonce(self, address: str, proxy_url=None, retries=5):
        url = f"{self.AUTH_API}/auth/nonce"
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(url=url, headers=self.AUTH_HEADERS[address], proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch Nonce Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def auth_verify(self, account: str, address: str, nonce: str, proxy_url=None, retries=5):
        url = f"{self.AUTH_API}/auth/verify"
        data = json.dumps(self.generate_payload(account, address, nonce))
        headers = {
            **self.AUTH_HEADERS[address],
            "Content-Length": str(len(data)),
            "Content-Type": "application/json"
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, data=data, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        result = await response.json()

                        raw_cookies = response.headers.getall('Set-Cookie', [])
                        if raw_cookies:
                            cookie = SimpleCookie()
                            cookie.load("\n".join(raw_cookies))
                            cookie_string = "; ".join([f"{key}={morsel.value}" for key, morsel in cookie.items()])
                            self.session_v1[address] = cookie_string

                            return result
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Login Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def verify_referral(self, address: str, proxy_url=None, retries=5):
        url = f"{self.BASE_API}/referrals/verify"
        data = json.dumps({"referralCode": self.REF_CODE})
        headers = {
            **self.BASE_HEADERS[address],
            "Content-Length": str(len(data)),
            "Content-Type": "application/json",
            "Cookie": f"{self.session_v1[address]}; {self.session_v4[address]}"
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, data=data, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Verify Referreal Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def users_data(self, address: str, proxy_url=None, retries=5):
        url = f"{self.AUTH_API}/users/me"
        headers = {
            **self.AUTH_HEADERS[address],
            "Authorization": f"Bearer {self.access_tokens[address]}",
            "Cookie": f"{self.session_v1[address]}"
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Status  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch user data Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def claim_credits(self, address: str, proxy_url=None, retries=5):
        url = f"{self.AUTH_API}/credits/claim"
        headers = {
            **self.AUTH_HEADERS[address],
            "Authorization": f"Bearer {self.access_tokens[address]}",
            "Content-Length": "0",
            "Cookie": f"{self.session_v1[address]}"
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.CYAN+Style.BRIGHT}Mining  :{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Not Claimed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def loyalities_rules(self, address: str, loyality_type: str, proxy_url=None, retries=5):
        url = f"{self.BASE_API}/loyalties/rules?type={loyality_type}"
        headers = {
            **self.BASE_HEADERS[address],
            "Cookie": f"{self.session_v1[address]}; {self.session_v4[address]}"
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.get(url=url, headers=headers, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Fetch Status Failed  {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def claim_loyalities(self, address: str, rules_id: str, proxy_url=None, retries=5):
        url = f"{self.BASE_API}/loyalties/rules"
        data = json.dumps({"ruleIds": [ rules_id ]})
        headers = {
            **self.BASE_HEADERS[address],
            "Content-Length": str(len(data)),
            "Content-Type": "application/json",
            "Cookie": f"{self.session_v1[address]}; {self.session_v4[address]}"
        }
        for attempt in range(retries):
            connector, proxy, proxy_auth = self.build_proxy_config(proxy_url)
            try:
                async with ClientSession(connector=connector, timeout=ClientTimeout(total=60)) as session:
                    async with session.post(url=url, headers=headers, data=data, proxy=proxy, proxy_auth=proxy_auth) as response:
                        response.raise_for_status()
                        return await response.json()
            except (Exception, ClientResponseError) as e:
                if attempt < retries - 1:
                    await asyncio.sleep(5)
                    continue
                self.log(
                    f"{Fore.BLUE+Style.BRIGHT}Check-In:{Style.RESET_ALL}"
                    f"{Fore.RED+Style.BRIGHT} Failed {Style.RESET_ALL}"
                    f"{Fore.MAGENTA+Style.BRIGHT}-{Style.RESET_ALL}"
                    f"{Fore.YELLOW+Style.BRIGHT} {str(e)} {Style.RESET_ALL}"
                )

        return None
    
    async def process_check_connection(self, address: str, use_proxy: bool, rotate_proxy: bool):
        while True:
            proxy = self.get_next_proxy_for_account(address) if use_proxy else None
            self.log(
                f"{Fore.CYAN+Style.BRIGHT}Proxy   :{Style.RESET_ALL}"
                f"{Fore.WHITE+Style.BRIGHT} {proxy} {Style.RESET_ALL}"
            )

            is_valid = await self.check_connection(proxy)
            if not is_valid:
                if rotate_proxy:
                    proxy = self.rotate_proxy_for_account(address)
                    await asyncio.sleep(1)
                    continue

                return False

            return True
    
    async def process_user_login(self, account: str, address: str, use_proxy: bool, rotate_proxy: bool):
        is_valid = await self.process_check_connection(address, use_proxy, rotate_proxy)
        if is_valid:
            proxy = self.get_next_proxy_for_account(address) if use_proxy else None

            auth_nonce = await self.auth_nonce(address, proxy)
            if not auth_nonce: return

            nonce = auth_nonce.get("nonce")

            auth_verify = await self.auth_verify(account, address, nonce, proxy)
            if not auth_verify: return False

            session_v4_payload = {
                "token": auth_verify["token"],
                "userId": auth_verify["tokenData"]["userId"],
                "snagUserId": auth_verify["tokenData"]["snagUserId"],
                "address": auth_verify["address"],
                "chainId": auth_verify["tokenData"]["chainId"],
                "expiresAt": auth_verify["expiresAt"],
                "newAccount": auth_verify["tokenData"]["newAccount"],
                "refreshToken": auth_verify["refreshToken"]
            }

            self.session_v4[address] = "@nitrograph/session-v4=" + quote(
                json.dumps(session_v4_payload, separators=(",", ":"))
            )

            self.access_tokens[address] = auth_verify["token"]
            self.refresh_tokens[address] = auth_verify["refreshToken"]

            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Status  :{Style.RESET_ALL}"
                f"{Fore.GREEN + Style.BRIGHT} Login Success {Style.RESET_ALL}"
            )

            # await self.verify_referral(address, proxy)

            return True

    async def process_accounts(self, account: str, address: str, use_proxy: bool, rotate_proxy: bool):
        logined = await self.process_user_login(account, address, use_proxy, rotate_proxy)
        if logined:
            proxy = self.get_next_proxy_for_account(address) if use_proxy else None

            user = await self.users_data(address, proxy)
            if not user: return

            points = user.get("data", {}).get("points", 0)
            credits = user.get("data", {}).get("credits", 0)
            streak_details = user.get("data", {}).get("streakDetails", {})
            mining_details = user.get("data", {}).get("miningDetails", {})

            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Points  :{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {points} XP {Style.RESET_ALL}"
            )
            self.log(
                f"{Fore.CYAN + Style.BRIGHT}Credits :{Style.RESET_ALL}"
                f"{Fore.WHITE + Style.BRIGHT} {credits} $NITRO {Style.RESET_ALL}"
            )

            pool_amount = mining_details.get("claimPoolAmount", 0)
            last_claims = mining_details.get("lastClaimAtTimestampMs", None)
            next_claims = mining_details.get("nextClaimAtTimestampMs", None)

            if pool_amount > 0:
                if last_claims is None:
                    claim = await self.claim_credits(address, proxy)
                    if claim:
                        reward = claim.get("claimedAmount")

                        self.log(
                            f"{Fore.CYAN + Style.BRIGHT}Mining  :{Style.RESET_ALL}"
                            f"{Fore.GREEN + Style.BRIGHT} Claimed {Style.RESET_ALL}"
                            f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                            f"{Fore.CYAN + Style.BRIGHT} Reward: {Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT}{reward} $NITRO {Style.RESET_ALL}"
                        )

                else:
                    next_claim_ts = next_claims / 1000
                    now_time = int(time.time())

                    if next_claim_ts < now_time:
                        claim = await self.claim_credits(address, proxy)
                        if claim:
                            reward = claim.get("claimedAmount")

                            self.log(
                                f"{Fore.CYAN + Style.BRIGHT}Mining  :{Style.RESET_ALL}"
                                f"{Fore.GREEN + Style.BRIGHT} Claimed {Style.RESET_ALL}"
                                f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                                f"{Fore.CYAN + Style.BRIGHT} Reward: {Style.RESET_ALL}"
                                f"{Fore.WHITE + Style.BRIGHT}{reward} $NITRO {Style.RESET_ALL}"
                            )
                    else:
                        next_claims_wib = datetime.fromtimestamp(next_claim_ts).astimezone(wib).strftime('%x %X %Z')
                        self.log(
                            f"{Fore.CYAN + Style.BRIGHT}Mining  :{Style.RESET_ALL}"
                            f"{Fore.YELLOW + Style.BRIGHT} Not Time to Claim {Style.RESET_ALL}"
                            f"{Fore.MAGENTA + Style.BRIGHT}-{Style.RESET_ALL}"
                            f"{Fore.CYAN + Style.BRIGHT} Claim at {Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT}{next_claims_wib}{Style.RESET_ALL}"
                        )
            else:
                self.log(
                    f"{Fore.CYAN + Style.BRIGHT}Mining  :{Style.RESET_ALL}"
                    f"{Fore.YELLOW + Style.BRIGHT} No Available Credits to Claim {Style.RESET_ALL}"
                )

            # loyalities = await self.loyalities_rules(address, "DAILY_CLAIM", proxy)
            # if loyalities:

            #     for loyality in loyalities:
            #         rules_id = loyality.get("id")

            #         claim = await self.claim_loyalities(address, rules_id, proxy)
            #         if claim:
            #             message = claim.get("message")

            #             self.log(
            #                 f"{Fore.CYAN + Style.BRIGHT}Check-In:{Style.RESET_ALL}"
            #                 f"{Fore.GREEN + Style.BRIGHT} {message} {Style.RESET_ALL}"
            #             )

    async def main(self):
        try:
            with open('accounts.txt', 'r') as file:
                accounts = [line.strip() for line in file if line.strip()]

            proxy_choice, rotate_proxy = self.print_question()

            while True:
                self.clear_terminal()
                self.welcome()
                self.log(
                    f"{Fore.GREEN + Style.BRIGHT}Account's Total: {Style.RESET_ALL}"
                    f"{Fore.WHITE + Style.BRIGHT}{len(accounts)}{Style.RESET_ALL}"
                )

                use_proxy = True if proxy_choice == 1 else False
                if use_proxy:
                    await self.load_proxies()

                separator = "=" * 25
                for account in accounts:
                    if account:
                        address = self.generate_address(account)
                        self.log(
                            f"{Fore.CYAN + Style.BRIGHT}{separator}[{Style.RESET_ALL}"
                            f"{Fore.WHITE + Style.BRIGHT} {self.mask_account(address)} {Style.RESET_ALL}"
                            f"{Fore.CYAN + Style.BRIGHT}]{separator}{Style.RESET_ALL}"
                        )

                        if not address:
                            self.log(
                                f"{Fore.CYAN + Style.BRIGHT}Status  :{Style.RESET_ALL}"
                                f"{Fore.RED + Style.BRIGHT} Invalid Private Key or Library Version Not Supported {Style.RESET_ALL}"
                            )
                            continue

                        user_agent = FakeUserAgent().random

                        self.BASE_HEADERS[address] = {
                            "Accept": "application/json, text/plain, */*",
                            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                            "Origin": "https://community.nitrograph.com",
                            "Referer": "https://community.nitrograph.com/app/missions",
                            "Sec-Fetch-Dest": "empty",
                            "Sec-Fetch-Mode": "cors",
                            "Sec-Fetch-Site": "same-origin",
                            "User-Agent": user_agent
                        }

                        self.AUTH_HEADERS[address] = {
                            "Accept": "application/json, text/plain, */*",
                            "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
                            "Origin": "https://community.nitrograph.com",
                            "Referer": "https://community.nitrograph.com/",
                            "Sec-Fetch-Dest": "empty",
                            "Sec-Fetch-Mode": "cors",
                            "Sec-Fetch-Site": "same-site",
                            "User-Agent": user_agent
                        }
                        
                        await self.process_accounts(account, address, use_proxy, rotate_proxy)

                self.log(f"{Fore.CYAN + Style.BRIGHT}={Style.RESET_ALL}"*72)
                
                delay = 24 * 60 * 60
                while delay > 0:
                    formatted_time = self.format_seconds(delay)
                    print(
                        f"{Fore.CYAN+Style.BRIGHT}[ Wait for{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} {formatted_time} {Style.RESET_ALL}"
                        f"{Fore.CYAN+Style.BRIGHT}... ]{Style.RESET_ALL}"
                        f"{Fore.WHITE+Style.BRIGHT} | {Style.RESET_ALL}"
                        f"{Fore.BLUE+Style.BRIGHT}All Accounts Have Been Processed...{Style.RESET_ALL}",
                        end="\r",
                        flush=True
                    )
                    await asyncio.sleep(1)
                    delay -= 1

        except FileNotFoundError:
            self.log(f"{Fore.RED}File 'accounts.txt' Not Found.{Style.RESET_ALL}")
            return
        except Exception as e:
            self.log(f"{Fore.RED+Style.BRIGHT}Error: {e}{Style.RESET_ALL}")
            raise e

if __name__ == "__main__":
    try:
        bot = NitroGraph()
        asyncio.run(bot.main())
    except KeyboardInterrupt:
        print(
            f"{Fore.CYAN + Style.BRIGHT}[ {datetime.now().astimezone(wib).strftime('%x %X %Z')} ]{Style.RESET_ALL}"
            f"{Fore.WHITE + Style.BRIGHT} | {Style.RESET_ALL}"
            f"{Fore.RED + Style.BRIGHT}[ EXIT ] NitroGraph - BOT{Style.RESET_ALL}                                       "                              
        )