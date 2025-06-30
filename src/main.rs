use std::str::FromStr;

use poem::{Route, Server, get, handler, listener::TcpListener, post, web::Json};
use serde::{Deserialize, Serialize};
use solana_client::rpc_client::RpcClient;

use solana_sdk::{
    instruction::Instruction,
    program_pack::Pack,
    pubkey::Pubkey,
    signature::Signature,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use spl_associated_token_account::{
    get_associated_token_address, instruction::create_associated_token_account,
};
use spl_memo;
use spl_token::{instruction as token_instruction, state::Mint};

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
async fn send_sol(Json(req): Json<RequestTransferBalance>) -> Json<TransferResponse> {
    let client = RpcClient::new("https://api.testnet.solana.com".to_string());

    let from_keypair = match bs58::decode(&req.from).into_vec() {
        Ok(bytes) => match Keypair::from_bytes(&bytes) {
            Ok(keypair) => keypair,
            Err(_) => {
                return Json(TransferResponse::Error {
                    success: false,
                    error: "Invalid secret key".to_string(),
                });
            }
        },
        Err(_) => {
            return Json(TransferResponse::Error {
                success: false,
                error: "Invalid secret key format".to_string(),
            });
        }
    };

    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(TransferResponse::Error {
                success: false,
                error: "Invalid destination".to_string(),
            });
        }
    };

    let lamports = req.lamports;
    let instruction = system_instruction::transfer(&from_keypair.pubkey(), &to_pubkey, lamports);

    let recent_blockhash = match client.get_latest_blockhash() {
        Ok(blockhash) => blockhash,
        Err(_) => {
            return Json(TransferResponse::Error {
                success: false,
                error: "Failed to get blockhash".to_string(),
            });
        }
    };

    let transaction = Transaction::new_signed_with_payer(
        &[instruction.clone()],
        Some(&from_keypair.pubkey()),
        &[&from_keypair],
        recent_blockhash,
    );

    match client.send_and_confirm_transaction(&transaction) {
        Ok(_) => Json(TransferResponse::Success {
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
        }),
        Err(err) => Json(TransferResponse::Error {
            success: false,
            error: format!("Transaction failed: {}", err),
        }),
    }
}

//-- spl transfer token =================================================================

#[derive(Serialize, Deserialize)]
struct SPLTokenTransferRequest {
    owner: String,
    destination: String,
    mint: String,
    amount: f64,
    memo: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct SPLAccountMeta {
    pub pubkey: String,
    pub isSigner: bool,
}

#[derive(Serialize, Deserialize)]
pub struct SPLTransferResponseData {
    pub program_id: String,
    pub accounts: Vec<SPLAccountMeta>,
    pub instruction_data: String,
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

pub fn get_token_amount_with_decimals(amount: f64, decimals: u8) -> u64 {
    (amount * 10_f64.powi(decimals as i32)) as u64
}

pub fn create_spl_token_transaction(
    amount: u64,
    from: &Pubkey,
    to: &Pubkey,
    token_mint: &Pubkey,
    payer: &Pubkey,
    memo: Option<String>,
    _decimals: u8,
) -> Result<(Vec<Instruction>, Pubkey), poem::Error> {
    let mut instructions = Vec::new();

    let from_ata = get_associated_token_address(from, token_mint);
    let to_ata = get_associated_token_address(to, token_mint);

    let rpc_client = RpcClient::new("https://api.testnet.solana.com".to_string());

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
            .map_err(|e| {
                poem::Error::from_string(e.to_string(), poem::http::StatusCode::BAD_REQUEST)
            })?;
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
async fn transfer_spl_token(Json(req): Json<SPLTokenTransferRequest>) -> Json<SPLTransferResponse> {
    let client = RpcClient::new("https://api.testnet.solana.com".to_string());

    let from_keypair = match bs58::decode(&req.owner).into_vec() {
        Ok(bytes) => match Keypair::from_bytes(&bytes) {
            Ok(keypair) => keypair,
            Err(_) => {
                return Json(SPLTransferResponse::Error {
                    success: false,
                    error: "Invalid secret key".to_string(),
                });
            }
        },
        Err(_) => {
            return Json(SPLTransferResponse::Error {
                success: false,
                error: "Invalid secret key format".to_string(),
            });
        }
    };

    let to_pubkey = match Pubkey::from_str(&req.destination) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(SPLTransferResponse::Error {
                success: false,
                error: "Invalid destination public key".to_string(),
            });
        }
    };

    let token_mint = match Pubkey::from_str(&req.mint) {
        Ok(pubkey) => pubkey,
        Err(_) => {
            return Json(SPLTransferResponse::Error {
                success: false,
                error: "Invalid token mint address".to_string(),
            });
        }
    };

    let mint_info = match client.get_account(&token_mint) {
        Ok(account) => account,
        Err(_) => {
            return Json(SPLTransferResponse::Error {
                success: false,
                error: "Token mint not found".to_string(),
            });
        }
    };

    let mint_data = match Mint::unpack(&mint_info.data) {
        Ok(data) => data,
        Err(e) => {
            return Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Failed to parse mint account: {}", e),
            });
        }
    };

    let amount = get_token_amount_with_decimals(req.amount, mint_data.decimals);

    let (instructions, payer) = match create_spl_token_transaction(
        amount,
        &from_keypair.pubkey(),
        &to_pubkey,
        &token_mint,
        &from_keypair.pubkey(),
        req.memo.clone(),
        mint_data.decimals,
    ) {
        Ok(result) => result,
        Err(e) => {
            return Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Failed to create transaction: {}", e),
            });
        }
    };

    let recent_blockhash = match client.get_latest_blockhash() {
        Ok(blockhash) => blockhash,
        Err(err) => {
            return Json(SPLTransferResponse::Error {
                success: false,
                error: format!("Failed to get blockhash: {}", err),
            });
        }
    };

    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer),
        &[&from_keypair],
        recent_blockhash,
    );

    match client.send_and_confirm_transaction(&transaction) {
        Ok(_) => {
            let primary_ix = &instructions[0];
            let accounts = primary_ix
                .accounts
                .iter()
                .map(|acc| SPLAccountMeta {
                    pubkey: acc.pubkey.to_string(),
                    isSigner: acc.is_signer,
                })
                .collect();

            Json(SPLTransferResponse::Success {
                success: true,
                data: SPLTransferResponseData {
                    program_id: primary_ix.program_id.to_string(),
                    accounts,
                    instruction_data: bs58::encode(&primary_ix.data).into_string(),
                },
            })
        }
        Err(err) => Json(SPLTransferResponse::Error {
            success: false,
            error: format!("Transaction failed: {}", err),
        }),
    }
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
async fn sign_message(Json(req): Json<SignMessageRequest>) -> Json<SignMessageResponse> {
    if req.message.is_empty() || req.secret.is_empty() {
        return Json(SignMessageResponse::Error {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }

    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(SignMessageResponse::Error {
                success: false,
                error: "Invalid base58 secret key".to_string(),
            });
        }
    };

    let keypair = match Keypair::from_bytes(&secret_bytes) {
        Ok(kp) => kp,
        Err(_) => {
            return Json(SignMessageResponse::Error {
                success: false,
                error: "Invalid keypair bytes".to_string(),
            });
        }
    };

    let signature = keypair.sign_message(req.message.as_bytes());
    Json(SignMessageResponse::Success {
        success: true,
        data: SignMessageData {
            signature: general_purpose::STANDARD.encode(signature.as_ref()),
            public_key: keypair.pubkey().to_string(),
            message: req.message,
        },
    })
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
async fn verify_message(Json(req): Json<VerifyMessageRequest>) -> Json<VerifyMessageResponse> {
    let pubkey = match Pubkey::from_str(&req.pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return Json(VerifyMessageResponse::Error {
                success: false,
                error: "Invalid public key format".to_string(),
            });
        }
    };

    let sig_bytes = match general_purpose::STANDARD.decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Json(VerifyMessageResponse::Error {
                success: false,
                error: "Invalid base64 signature".to_string(),
            });
        }
    };

    let signature = match Signature::try_from(sig_bytes.as_slice()) {
        Ok(sig) => sig,
        Err(_) => {
            return Json(VerifyMessageResponse::Error {
                success: false,
                error: "Invalid signature bytes".to_string(),
            });
        }
    };

    let valid = signature.verify(pubkey.as_ref(), req.message.as_bytes());

    Json(VerifyMessageResponse::Success {
        success: true,
        data: VerifyMessageData {
            valid,
            message: req.message,
            pubkey: req.pubkey,
        },
    })
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
