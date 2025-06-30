use std::str::FromStr;

use poem::{
    Result, Route, Server, get, handler, http::StatusCode, listener::TcpListener, post, web::Json,
};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;

use solana_sdk::{
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Signature,
    signature::{Keypair, Signer},
    system_instruction,
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use spl_memo;
use spl_token::{
    instruction as token_instruction,
    state::{Account as TokenAccount, Mint},
};

use base64::{Engine as _, engine::general_purpose};

#[derive(Deserialize, Serialize)]
struct RequestData {
    value: String,
}

#[handler]
async fn health() -> String {
    "OK".to_string()
}

#[derive(Serialize, Deserialize)]
struct KeypairData {
    pubkey: String,
    secret: String,
}

#[derive(Serialize, Deserialize)]
struct KeypairResponse {
    success: bool,
    data: KeypairData,
}

#[handler]
async fn generate_keypair() -> Json<KeypairResponse> {
    let keypair = solana_sdk::signature::Keypair::new();
    let response = KeypairResponse {
        success: true,
        data: KeypairData {
            pubkey: keypair.pubkey().to_string(),
            secret: keypair.to_base58_string(),
        },
    };
    Json(response)
}

/// sol transfer ================================================================

#[derive(Serialize, Deserialize)]
struct RequestTransferBalance {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize, Deserialize)]
struct TransferResponseData {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum TransferResponse {
    Success {
        success: bool,
        data: TransferResponseData,
    },
    Error {
        success: bool,
        error: String,
    },
}

#[handler]
async fn send_sol(Json(req): Json<RequestTransferBalance>) -> Result<Json<TransferResponse>> {
    let client = RpcClient::new(
        std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.testnet.solana.com".to_string()),
    );

    if req.from.is_empty() || req.to.is_empty() {
        return Ok(Json(TransferResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        }));
    }

    if req.lamports == 0 {
        return Ok(Json(TransferResponse::Error {
            success: false,
            error: "Lamports must be greater than zero".to_string(),
        }));
    }

    let from_keypair = match bs58::decode(&req.from).into_vec() {
        Ok(bytes) => match Keypair::from_bytes(&bytes) {
            Ok(keypair) => keypair,
            Err(e) => {
                return Ok(Json(TransferResponse::Error {
                    success: false,
                    error: format!("Invalid secret key: {}", e),
                }));
            }
        },
        Err(e) => {
            return Ok(Json(TransferResponse::Error {
                success: false,
                error: format!("Invalid secret key format: {}", e),
            }));
        }
    };

    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            return Ok(Json(TransferResponse::Error {
                success: false,
                error: format!("Invalid destination: {}", e),
            }));
        }
    };

    let balance = match client.get_balance(&from_keypair.pubkey()) {
        Ok(balance) => balance,
        Err(e) => {
            return Ok(Json(TransferResponse::Error {
                success: false,
                error: format!("Failed to get balance: {}", e),
            }));
        }
    };
    if balance < req.lamports {
        return Ok(Json(TransferResponse::Error {
            success: false,
            error: "Insufficient balance".to_string(),
        }));
    }

    if client.get_account(&to_pubkey).is_err() {
        return Ok(Json(TransferResponse::Error {
            success: false,
            error: "Invalid destination account".to_string(),
        }));
    }

    let instruction =
        system_instruction::transfer(&from_keypair.pubkey(), &to_pubkey, req.lamports);
    Ok(Json(TransferResponse::Success {
        success: true,
        data: TransferResponseData {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .iter()
                .map(|acc| acc.pubkey.to_string())
                .collect(),
            instruction_data: bs58::encode(&instruction.data).into_string(),
        },
    }))
}

//-- spl transfer token =================================================================

#[derive(Serialize, Deserialize)]
struct SPLTokenTransferRequest {
    owner: String,
    destination: String,
    mint: String,
    amount: u64,
    memo: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SPLAccountMeta {
    pubkey: String,
    is_signer: bool,
}

#[derive(Serialize, Deserialize)]
pub struct SPLTransferResponseData {
    program_id: String,
    accounts: Vec<SPLAccountMeta>,
    instruction_data: String,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum SPLTransferResponse {
    Success {
        success: bool,
        data: SPLTransferResponseData,
    },
    Error {
        success: bool,
        error: String,
    },
}

pub fn create_spl_token_transaction(
    amount: u64,
    from: &Pubkey,
    to: &Pubkey,
    token_mint: &Pubkey,
    payer: &Pubkey,
    memo: Option<String>,
    _decimals: u8,
) -> Result<(Vec<Instruction>, Pubkey), String> {
    let mut instructions = Vec::new();

    let from_ata = get_associated_token_address(from, token_mint);
    let to_ata = get_associated_token_address(to, token_mint);

    let rpc_client = RpcClient::new(
        std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.testnet.solana.com".to_string()),
    );

    if rpc_client.get_account(&from_ata).is_err() {
        let create_ata_instruction =
            create_associated_token_account(payer, from, token_mint, &spl_token::id());
        instructions.push(create_ata_instruction);
    }

    if rpc_client.get_account(&to_ata).is_err() {
        let create_to_ata_instruction =
            create_associated_token_account(payer, to, token_mint, &spl_token::id());
        instructions.push(create_to_ata_instruction);
    }

    let transfer_instruction =
        token_instruction::transfer(&spl_token::id(), &from_ata, &to_ata, from, &[], amount)
            .map_err(|e| format!("Failed to create transfer instruction: {}", e))?;
    instructions.push(transfer_instruction);

    if let Some(memo_text) = memo {
        let memo_instruction = Instruction {
            program_id: spl_memo::id(),
            accounts: Vec::new(),
            data: memo_text.into_bytes(),
        };
        instructions.push(memo_instruction);
    }

    Ok((instructions, *payer))
}

#[handler]
async fn transfer_spl_token(
    Json(req): Json<SPLTokenTransferRequest>,
) -> Result<Json<SPLTransferResponse>> {
    let client = RpcClient::new(
        std::env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "https://api.testnet.solana.com".to_string()),
    );

    if req.owner.is_empty() || req.destination.is_empty() || req.mint.is_empty() {
        return Ok(Json(SPLTransferResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        }));
    }

    if req.amount == 0 {
        return Ok(Json(SPLTransferResponse::Error {
            success: false,
            error: "Amount must be greater than zero".to_string(),
        }));
    }

    let from_keypair = match bs58::decode(&req.owner).into_vec() {
        Ok(bytes) => match Keypair::from_bytes(&bytes) {
            Ok(keypair) => keypair,
            Err(e) => {
                return Ok(Json(SPLTransferResponse::Error {
                    success: false,
                    error: format!("Invalid secret key: {}", e),
                }));
            }
        },
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Invalid secret key format: {}", e),
            }));
        }
    };

    let to_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Invalid destination public key: {}", e),
            }));
        }
    };

    let token_mint = match Pubkey::from_str(&req.mint) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Invalid token mint address: {}", e),
            }));
        }
    };

    println!("Checking mint: {}", token_mint); // Log mint address
    let mint_info = match client.get_account(&token_mint) {
        Ok(account) => account,
        Err(e) => {
            println!("Mint fetch error: {}", e); // Log RPC error
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Token mint not found: {}", e),
            }));
        }
    };

    let mint_data = match Mint::unpack(&mint_info.data) {
        Ok(data) => data,
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Failed to parse mint account: {}", e),
            }));
        }
    };

    let balance = match client.get_balance(&from_keypair.pubkey()) {
        Ok(balance) => balance,
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Failed to get balance: {}", e),
            }));
        }
    };
    if balance < 2_000_000 {
        return Ok(Json(SPLTransferResponse::Error {
            success: false,
            error: "Insufficient SOL for ATA creation".to_string(),
        }));
    }

    // Check token balance
    let from_ata = get_associated_token_address(&from_keypair.pubkey(), &token_mint);
    let token_account = match client.get_account(&from_ata) {
        Ok(account) => account,
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Source token account not found: {}", e),
            }));
        }
    };
    let token_data = match TokenAccount::unpack(&token_account.data) {
        Ok(data) => data,
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Failed to parse token account: {}", e),
            }));
        }
    };
    if token_data.amount < req.amount {
        return Ok(Json(SPLTransferResponse::Error {
            success: false,
            error: "Insufficient token balance".to_string(),
        }));
    }

    let (instructions, _payer) = match create_spl_token_transaction(
        req.amount,
        &from_keypair.pubkey(),
        &to_pubkey,
        &token_mint,
        &from_keypair.pubkey(),
        req.memo.clone(),
        mint_data.decimals,
    ) {
        Ok(result) => result,
        Err(e) => {
            return Ok(Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Failed to create transaction: {}", e),
            }));
        }
    };

    let primary_ix = instructions
        .iter()
        .find(|ix| ix.program_id == spl_token::id())
        .ok_or_else(|| {
            poem::Error::from_string(
                "No transfer instruction found".to_string(),
                StatusCode::BAD_REQUEST,
            )
        })?;

    let accounts = primary_ix
        .accounts
        .iter()
        .map(|acc| SPLAccountMeta {
            pubkey: acc.pubkey.to_string(),
            is_signer: acc.is_signer,
        })
        .collect();

    Ok(Json(SPLTransferResponse::Success {
        success: true,
        data: SPLTransferResponseData {
            program_id: primary_ix.program_id.to_string(),
            accounts,
            instruction_data: bs58::encode(&primary_ix.data).into_string(),
        },
    }))
}

// signing message --------------------- ====================

#[derive(Deserialize)]
struct SignMessageRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct SignMessageData {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum SignMessageResponse {
    Success {
        success: bool,
        data: SignMessageData,
    },
    Error {
        success: bool,
        error: String,
    },
}

#[handler]
async fn sign_message(Json(req): Json<SignMessageRequest>) -> Result<Json<SignMessageResponse>> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Ok(Json(SignMessageResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        }));
    }

    if req.message.len() > 1024 {
        return Ok(Json(SignMessageResponse::Error {
            success: false,
            error: "Message too long".to_string(),
        }));
    }

    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(e) => {
            return Ok(Json(SignMessageResponse::Error {
                success: false,
                error: format!("Invalid base58 secret key: {}", e),
            }));
        }
    };

    if secret_bytes.len() != 64 {
        return Ok(Json(SignMessageResponse::Error {
            success: false,
            error: "Invalid secret key length".to_string(),
        }));
    }

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(keypair) => keypair,
        Err(e) => {
            return Ok(Json(SignMessageResponse::Error {
                success: false,
                error: format!("Invalid keypair bytes: {}", e),
            }));
        }
    };

    let signature = keypair.sign_message(req.message.as_bytes());

    Ok(Json(SignMessageResponse::Success {
        success: true,
        data: SignMessageData {
            signature: general_purpose::STANDARD.encode(signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: req.message,
        },
    }))
}

/// - verifying ========================
#[derive(Deserialize)]
struct VerifyMessageRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct VerifyMessageData {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum VerifyMessageResponse {
    Success {
        success: bool,
        data: VerifyMessageData,
    },
    Error {
        success: bool,
        error: String,
    },
}

#[handler]
async fn verify_message(
    Json(req): Json<VerifyMessageRequest>,
) -> Result<Json<VerifyMessageResponse>> {
    if req.message.is_empty() || req.signature.is_empty() || req.pubkey.is_empty() {
        return Ok(Json(VerifyMessageResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        }));
    }

    if req.message.len() > 1024 {
        return Ok(Json(VerifyMessageResponse::Error {
            success: false,
            error: "Message too long".to_string(),
        }));
    }

    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pubkey) => pubkey,
        Err(e) => {
            return Ok(Json(VerifyMessageResponse::Error {
                success: false,
                error: format!("Invalid public key format: {}", e),
            }));
        }
    };

    let sig_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("Base64 decode error: {}", e);
            return Ok(Json(VerifyMessageResponse::Error {
                success: false,
                error: format!("Invalid base64 signature: {}", e),
            }));
        }
    };

    if sig_bytes.len() != 64 {
        return Ok(Json(VerifyMessageResponse::Error {
            success: false,
            error: "Invalid signature length".to_string(),
        }));
    }

    let signature = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(e) => {
            return Ok(Json(VerifyMessageResponse::Error {
                success: false,
                error: format!("Invalid signature bytes: {}", e),
            }));
        }
    };

    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());
    println!("Verification result: {}", valid);

    Ok(Json(VerifyMessageResponse::Success {
        success: true,
        data: VerifyMessageData {
            valid,
            message: req.message,
            pubkey: req.pubkey,
        },
    }))
}
#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    let app = Route::new()
        .at("/health", get(health))
        .at("/keypair", post(generate_keypair))
        .at("/send/sol", post(send_sol))
        .at("/send/token", post(transfer_spl_token))
        .at("/message/sign", post(sign_message))
        .at("/message/verify", post(verify_message));

    Server::new(TcpListener::bind("0.0.0.0:8000"))
        .run(app)
        .await
}
