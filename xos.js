require('dotenv').config();
const axios = require('axios');
const prompt = require('prompt-sync')();
const Captcha = require('2captcha');
const randomUseragent = require('random-useragent');
const { HttpsProxyAgent } = require('https-proxy-agent');
const fs = require('fs');
const { ethers } = require('ethers');

const colors = {
  reset: '\x1b[0m',
  cyan: '\x1b[36m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  white: '\x1b[37m',
  bold: '\x1b[1m',
};

const logger = {
  info: (msg) => console.log(`${colors.green}[✓] ${msg}${colors.reset}`),
  wallet: (msg) => console.log(`${colors.yellow}[➤] ${msg}${colors.reset}`),
  warn: (msg) => console.log(`${colors.yellow}[⚠] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[✅] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
  step: (msg) => console.log(`${colors.white}[➤] ${msg}${colors.reset}`),
  banner: () => {
    console.log(`${colors.cyan}${colors.bold}`);
    console.log(`---------------------------------------------`);
    console.log(`  XOS Testnet Auto Bot - Airdrop Insiders `);
    console.log(`---------------------------------------------${colors.reset}\n`);
  },
};

const USDC_ABI = [
  {
    inputs: [
      { internalType: 'address', name: 'spender', type: 'address' },
      { internalType: 'uint256', name: 'amount', type: 'uint256' },
    ],
    name: 'approve',
    outputs: [{ internalType: 'bool', name: '', type: 'bool' }],
    stateMutability: 'nonpayable',
    type: 'function',
  },
  {
    inputs: [
      { internalType: 'address', name: 'owner', type: 'address' },
      { internalType: 'address', name: 'spender', type: 'address' },
    ],
    name: 'allowance',
    outputs: [{ internalType: 'uint256', name: '', type: 'uint256' }],
    stateMutability: 'view',
    type: 'function',
  },
];

const SWAP_ROUTER_ABI = [
  {
    inputs: [
      {
        components: [
          { internalType: 'address', name: 'tokenIn', type: 'address' },
          { internalType: 'address', name: 'tokenOut', type: 'address' },
          { internalType: 'uint24', name: 'fee', type: 'uint24' },
          { internalType: 'address', name: 'recipient', type: 'address' },
          { internalType: 'uint256', name: 'amountIn', type: 'uint256' },
          { internalType: 'uint256', name: 'amountOutMinimum', type: 'uint256' },
          { internalType: 'uint160', name: 'sqrtPriceLimitX96', type: 'uint160' },
        ],
        internalType: 'struct IV3SwapRouter.ExactInputSingleParams',
        name: 'params',
        type: 'tuple',
      },
    ],
    name: 'exactInputSingle',
    outputs: [{ internalType: 'uint256', name: 'amountOut', type: 'uint256' }],
    stateMutability: 'payable',
    type: 'function',
  },
  {
    inputs: [
      {
        components: [
          { internalType: 'bytes', name: 'path', type: 'bytes' },
          { internalType: 'address', name: 'recipient', type: 'address' },
          { internalType: 'uint256', name: 'amountIn', type: 'uint256' },
          { internalType: 'uint256', name: 'amountOutMinimum', type: 'uint256' },
        ],
        internalType: 'struct IV3SwapRouter.ExactInputParams',
        name: 'params',
        type: 'tuple',
      },
    ],
    name: 'exactInput',
    outputs: [{ internalType: 'uint256', name: 'amountOut', type: 'uint256' }],
    stateMutability: 'payable',
    type: 'function',
  },
  {
    inputs: [{ internalType: 'bytes[]', name: 'data', type: 'bytes[]' }],
    name: 'multicall',
    outputs: [{ internalType: 'bytes[]', name: 'results', type: 'bytes[]' }],
    stateMutability: 'payable',
    type: 'function',
  },
];

const DID_REGISTRAR_ABI = [
  {
    inputs: [
      { internalType: 'string', name: 'name', type: 'string' },
      { internalType: 'address', name: 'owner', type: 'address' },
      { internalType: 'uint256', name: 'duration', type: 'uint256' },
      { internalType: 'address', name: 'resolver', type: 'address' },
      { internalType: 'address', name: 'addr', type: 'address' },
      { internalType: 'bool', name: 'reverseRecord', type: 'bool' },
      { internalType: 'address', name: 'referrer', type: 'address' },
    ],
    name: 'registerWithConfig',
    outputs: [],
    stateMutability: 'payable',
    type: 'function',
  },
];

const FAUCET_URL = 'https://faucet.x.ink';
const RPC_URL = 'https://testnet-rpc.x.ink/';
const CHAIN_ID = 1267;
const provider = new ethers.JsonRpcProvider(RPC_URL);

const DID_REGISTRAR_ADDRESS = '0xb8692493fe9baec1152b396188a8e6f0cfa4e4e7';
const SWAP_ROUTER_ADDRESS = '0xdc7d6b58c89a554b3fdc4b5b10de9b4dbf39fb40';
const WXOS_ADDRESS = '0x0aab67cf6f2e99847b9a95dec950b250d648c1bb';
const USDC_ADDRESS = '0xb2c1c007421f0eb5f4b3b3f38723c309bb208d7d';
const BONK_ADDRESS = '0x00309602f7977d45322279c4dd5cf61d16fd061b';
const BNB_ADDRESS = '0x83dfbe02dc1b1db11bc13a8fc7fd011e2dbbd7c0';
const JUP_ADDRESS = '0x26b597804318824a2e88cd717376f025e6bb2219';
const RESOLVER_ADDRESS = '0x17b1bfd1e30f374dbd821f2f52e277bc47829ceb';

const privateKeys = Object.keys(process.env)
  .filter((key) => key.startsWith('PRIVATE_KEY_'))
  .map((key) => process.env[key]);

let proxies = [];
try {
  proxies = fs.readFileSync('proxies.txt', 'utf8')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith('#'));
} catch (error) {
  logger.warn('No proxies.txt found or error reading file. Running without proxies.');
}

function getProxyAgent() {
  if (proxies.length === 0) return null;
  const proxy = proxies[Math.floor(Math.random() * proxies.length)];
  return new HttpsProxyAgent(proxy);
}

function getHeaders() {
  const userAgent = randomUseragent.getRandom();
  return {
    accept: 'application/json, text/plain, */*',
    'accept-language': 'en-US,en;q=0.7',
    'content-type': 'application/json',
    priority: 'u=1, i',
    'sec-ch-ua': '"Chromium";v="136", "Brave";v="136", "Not.A/Brand";v="99"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'sec-gpc': '1',
    Referer: `${FAUCET_URL}/`,
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'User-Agent': userAgent,
  };
}

async function solveRecaptcha(apiKey) {
  try {
    logger.loading('Solving reCAPTCHA...');
    const solver = new Captcha.Solver(apiKey);
    const { data } = await solver.recaptcha({
      googlekey: '6LcZ22gpAAAAAMbV-kv_3vUOKr8hju4T0iD2fG0s',
      pageurl: FAUCET_URL,
    });
    logger.success('reCAPTCHA solved');
    return data;
  } catch (error) {
    throw new Error(`Captcha solving failed: ${error.message}`);
  }
}

async function checkAddressEligibility(address) {
  try {
    logger.loading(`Checking eligibility for ${address}...`);
    const response = await axios.get(`${FAUCET_URL}/api/checkAddressEligibility?address=${address}`, {
      headers: getHeaders(),
      httpsAgent: getProxyAgent(),
    });
    logger.success('Eligibility checked');
    return response.data;
  } catch (error) {
    const message = error.response?.data?.message || error.message;
    throw new Error(`{ canClaim: false, message: "${message}" }`);
  }
}

async function checkInfo(address) {
  try {
    logger.loading(`Checking info for ${address}...`);
    const response = await axios.get(`${FAUCET_URL}/api/check-info?walletAddress=${address}`, {
      headers: getHeaders(),
      httpsAgent: getProxyAgent(),
    });
    logger.success('Info retrieved');
    return response.data;
  } catch (error) {
    throw new Error(`Info check failed: ${error.message}`);
  }
}

async function claimTokens(address, captchaToken) {
  try {
    logger.loading('Claiming tokens...');
    const payload = {
      address: address,
      token: '',
      v2Token: captchaToken,
      chain: 'XOS',
      couponId: '',
    };
    const response = await axios.post(`${FAUCET_URL}/api/sendToken`, payload, {
      headers: getHeaders(),
      httpsAgent: getProxyAgent(),
    });
    logger.success('Tokens claimed');
    return response.data;
  } catch (error) {
    throw new Error(`Token claim failed: ${error.message}`);
  }
}

async function claimFaucet() {
  const apiKey = prompt('Enter your 2Captcha API key: ');
  if (!apiKey) {
    logger.error('2Captcha API key is required.');
    return;
  }

  while (true) {
    const address = prompt('Enter your wallet address (or "exit" to return to menu): ');
    if (address.toLowerCase() === 'exit') break;

    if (!/^0x[a-fA-F0-9]{40}$/.test(address)) {
      logger.error('Invalid wallet address format. Please try again.');
      continue;
    }

    try {
      const eligibility = await checkAddressEligibility(address);
      if (!eligibility.canClaim) {
        logger.warn(`Eligibility: { canClaim: ${eligibility.canClaim}, message: "${eligibility.message}" }`);
        logger.step('Please enter a different address.');
        continue;
      }

      const info = await checkInfo(address);
      logger.info(`Account info: ${JSON.stringify(info)}`);

      const captchaToken = await solveRecaptcha(apiKey);
      const claimResult = await claimTokens(address, captchaToken);
      logger.success(`Claim result: ${JSON.stringify(claimResult)}`);
      logger.step('Claim successful! Enter another address to continue.');
    } catch (error) {
      logger.error(error.message);
    }
  }
}

async function registerOpenID() {
  if (privateKeys.length === 0) {
    logger.error('No private keys found in .env file.');
    return;
  }

  const domain = prompt('Enter your .xos domain name (e.g., vikitoshi): ');
  if (!domain || domain.includes('.xos')) {
    logger.error('Invalid domain name. Enter only the name without .xos.');
    return;
  }

  const minBalance = ethers.parseEther('0.1'); 
  for (const privateKey of privateKeys) {
    const wallet = new ethers.Wallet(privateKey, provider);
    try {
      const balance = await provider.getBalance(wallet.address);
      if (balance < minBalance) {
        logger.error(
          `Insufficient XOS for ${wallet.address}. Need at least 0.1 XOS, have ${ethers.formatEther(balance)} XOS.`
        );
        continue;
      }

      const contract = new ethers.Contract(DID_REGISTRAR_ADDRESS, DID_REGISTRAR_ABI, wallet);
      logger.wallet(`Registering ${domain}.xos for ${wallet.address}...`);
      const duration = 31536000; 
      const value = ethers.parseEther('0.05');
      const tx = await contract.registerWithConfig(
        domain,
        wallet.address,
        duration,
        RESOLVER_ADDRESS,
        wallet.address,
        true,
        '0x0000000000000000000000000000000000000000',
        { value }
      );

      logger.loading(`Transaction sent: ${tx.hash}`);
      const receipt = await tx.wait();
      logger.success(`Domain ${domain}.xos registered! Tx: https://testnet.xoscan.io/tx/${receipt.transactionHash}`);
    } catch (error) {
      logger.error(`Error registering for ${wallet.address}: ${error.message}`);
    }
  }
}

async function swapTokens() {
  if (privateKeys.length === 0) {
    logger.error('No private keys found in .env file.');
    return;
  }

  logger.step('Swap XOS Dex Submenu:');
  logger.info('1. XOS - USDC');
  logger.info('2. XOS - BONK');
  logger.info('3. XOS - BNB');
  logger.info('4. XOS - JUP');
  const choice = prompt('Select an option (1-4): ');

  let tokenOut;
  let isDirectSwap = false;
  switch (choice) {
    case '1':
      tokenOut = USDC_ADDRESS;
      isDirectSwap = true; 
      break;
    case '2':
      tokenOut = BONK_ADDRESS;
      break;
    case '3':
      tokenOut = BNB_ADDRESS;
      break;
    case '4':
      tokenOut = JUP_ADDRESS;
      break;
    default:
      logger.error('Invalid choice.');
      return;
  }

  const amountIn = prompt('Enter amount of XOS to swap (e.g., 0.001): ');
  const numTx = parseInt(prompt('Enter number of transactions: '), 10);
  if (isNaN(numTx) || numTx <= 0) {
    logger.error('Invalid number of transactions.');
    return;
  }

  let amountInWei;
  try {
    amountInWei = ethers.parseEther(amountIn);
  } catch (error) {
    logger.error('Invalid XOS amount.');
    return;
  }

  const minBalance = amountInWei + ethers.parseEther('0.015'); 
  for (const privateKey of privateKeys) {
    const wallet = new ethers.Wallet(privateKey, provider);
    try {
      const balance = await provider.getBalance(wallet.address);
      if (balance < minBalance) {
        logger.error(
          `Insufficient XOS for ${wallet.address}. Need at least ${ethers.formatEther(minBalance)} XOS, have ${ethers.formatEther(
            balance
          )} XOS.`
        );
        continue;
      }

      const wxosContract = new ethers.Contract(WXOS_ADDRESS, USDC_ABI, wallet);
      const swapContract = new ethers.Contract(SWAP_ROUTER_ADDRESS, SWAP_ROUTER_ABI, wallet);

      const allowance = await wxosContract.allowance(wallet.address, SWAP_ROUTER_ADDRESS);
      if (allowance < amountInWei) {
        logger.wallet(`Approving WXOS for ${wallet.address}...`);
        const approveTx = await wxosContract.approve(SWAP_ROUTER_ADDRESS, amountInWei, { gasLimit: 100000 });
        await approveTx.wait();
        logger.success(`Approval successful: ${approveTx.hash}`);
      } else {
        logger.info(`Sufficient allowance for ${wallet.address}`);
      }

      const amountOutMinimum = 0;

      for (let i = 0; i < numTx; i++) {
        logger.loading(`Performing swap ${i + 1}/${numTx} for ${wallet.address}...`);
        const deadline = Math.floor(Date.now() / 1000) + 1800;

        try {
          let encodedData;
          const swapInterface = new ethers.Interface(SWAP_ROUTER_ABI);

          if (isDirectSwap) {
            const normalizedWxosAddress = WXOS_ADDRESS.toLowerCase();
            const normalizedTokenOut = tokenOut.toLowerCase();
            const isTokenInWxos = normalizedWxosAddress < normalizedTokenOut;

            const swapParams = {
              tokenIn: isTokenInWxos ? WXOS_ADDRESS : tokenOut,
              tokenOut: isTokenInWxos ? tokenOut : WXOS_ADDRESS,
              fee: 500, 
              recipient: wallet.address,
              amountIn: amountInWei,
              amountOutMinimum,
              sqrtPriceLimitX96: 0,
            };

            encodedData = swapInterface.encodeFunctionData('exactInputSingle', [swapParams]);
          } else {
            const path = ethers.AbiCoder.defaultAbiCoder().encode(
              ['address', 'uint24', 'address', 'uint24', 'address'],
              [WXOS_ADDRESS, 500, USDC_ADDRESS, 500, tokenOut]
            );

            const swapParams = {
              path,
              recipient: wallet.address,
              amountIn: amountInWei,
              amountOutMinimum,
            };

            encodedData = swapInterface.encodeFunctionData('exactInput', [swapParams]);
          }

          const multicallData = [encodedData];

          let gasLimit;
          try {
            gasLimit = await swapContract.multicall.estimateGas(multicallData, { value: amountInWei });
            gasLimit = gasLimit * 120n / 100n; 
          } catch (gasError) {
            logger.warn(`Gas estimation failed: ${gasError.message}. Using default gas limit.`);
            gasLimit = isDirectSwap ? 200000 : 300000; 
          }

          const tx = await swapContract.multicall(multicallData, {
            value: amountInWei,
            gasLimit,
          });

          const receipt = await tx.wait();
          logger.success(`Swap successful! Tx: https://testnet.xoscan.io/tx/${receipt.transactionHash}`);
        } catch (swapError) {
          logger.error(`Swap ${i + 1}/${numTx} failed for ${wallet.address}: ${swapError.message}`);
          continue;
        }
      }
    } catch (error) {
      logger.error(`Error processing swaps for ${wallet.address}: ${error.message}`);
    }
  }
}

async function main() {
  logger.banner();

  while (true) {
    logger.step('Main Menu:');
    logger.info('1. Claim Faucet (Need 2Captcha API Key)');
    logger.info('2. Register Open ID Network');
    logger.info('3. Swap XOS Dex');
    logger.info('4. Exit');
    const choice = prompt('Select an option (1-4): ');

    if (choice === '1') await claimFaucet();
    else if (choice === '2') await registerOpenID();
    else if (choice === '3') await swapTokens();
    else if (choice === '4') {
      logger.success('Exiting...');
      break;
    } else {
      logger.error('Invalid choice. Please try again.');
    }
  }
}

main().catch((error) => logger.error(`Fatal error: ${error.message}`));