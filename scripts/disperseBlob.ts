import { disperser } from "./eigenDAClient/proto/disperser";
import { ChannelCredentials } from "@grpc/grpc-js";
import * as fs from 'fs';

const blobInfoPath = "./test/foundry/blobInfo/blobInfo.json";
const client = new disperser.DisperserClient("disperser-holesky.eigenda.xyz:443", ChannelCredentials.createSsl());
const disperseBlobRequest = new disperser.DisperseBlobRequest({ data: new Uint8Array([0, 1, 2, 3]) });

async function checkBlobStatus() {
    if (fs.existsSync(blobInfoPath)) {
        const blobInfo = JSON.parse(fs.readFileSync(blobInfoPath, "utf8"));
        let request_id_bytes = new Uint8Array(Buffer.from(blobInfo.request_id, 'hex'));

        const blobStatusRequest = new disperser.BlobStatusRequest({ request_id: request_id_bytes });

        return new Promise<boolean>((resolve) => {
            client.GetBlobStatus(blobStatusRequest, (error: Error | null, blobStatusReply?: disperser.BlobStatusReply) => {
                if (error) {
                    switch (error.message) {
                        case "5 NOT_FOUND: no metadata found for the requestID":
                            console.log("Blob has expired, disperse again");
                            resolve(true);
                            break;
                        default:
                            console.error("Error:", error);
                            resolve(false);
                    }
                } else if (blobStatusReply) {
                    console.log("Blob found, no need to disperse");
                    resolve(false);
                } else {
                    console.error("No reply from GetBlobStatus");
                    resolve(false);
                }
            });
        });
    } else {
        return true;
    }
}

(async () => {
    const needToDisperseBlob = await checkBlobStatus();

    if (needToDisperseBlob) {
        console.log("DisperseBlob");
        client.DisperseBlob(disperseBlobRequest, (error: Error | null, disperseBlobReply?: disperser.DisperseBlobReply) => {
            if (error) {
                console.error("Error:", error);
            } else if (disperseBlobReply) {
                console.log("Blob ID:", Buffer.from(disperseBlobReply.request_id).toString("hex"));

                const blobStatusRequest = new disperser.BlobStatusRequest({ request_id: disperseBlobReply.request_id });

                const blobStatusChecker = setInterval(() => {
                    client.GetBlobStatus(blobStatusRequest, (statusError: Error | null, blobStatusReply?: disperser.BlobStatusReply) => {
                        if (statusError) {
                            console.error("Status Error:", statusError);
                        } else if (blobStatusReply) {
                            switch (blobStatusReply.status) {
                                case disperser.BlobStatus.PROCESSING:
                                    console.log("Blob is currently being processed.");
                                    break;
                                case disperser.BlobStatus.DISPERSING:
                                    console.log("Blob is currently being dispersed.");
                                    break;
                                case disperser.BlobStatus.CONFIRMED:
                                    console.log("Blob has been confirmed.");
                                    let blobInfoWithRequestId = parseBlobInfo(disperseBlobReply, blobStatusReply);
                                    fs.writeFileSync(blobInfoPath, JSON.stringify(blobInfoWithRequestId, null, 2));
                                    clearInterval(blobStatusChecker);
                                    break;
                                case disperser.BlobStatus.FAILED:
                                    console.log("Blob has failed.");
                                    break;
                                case disperser.BlobStatus.FINALIZED:
                                    console.log("Blob has been finalized.");
                                    break;
                                case disperser.BlobStatus.INSUFFICIENT_SIGNATURES:
                                    console.log("Blob has insufficient signatures.");
                                    break;
                            }
                        } else {
                            console.error("No reply from GetBlobStatus");
                        }
                    });
                }, 30000);
            } else {
                console.error("No reply from DisperseBlob");
            }
        });
    }
})();

function parseBlobInfo(disperseBlobReply: disperser.DisperseBlobReply, blobStatusReply: disperser.BlobStatusReply) {
    const blobQuorumParams = blobStatusReply.info.blob_header.blob_quorum_params.map(param => ({
        quorum_number: param.quorum_number,
        adversary_threshold_percentage: param.adversary_threshold_percentage,
        confirmation_threshold_percentage: param.confirmation_threshold_percentage,
        chunk_length: param.chunk_length
    }));

    return {
        request_id: Buffer.from(disperseBlobReply.request_id).toString("hex"),
        blob_info: {
            blob_header: {
                commitment: {
                    x: Buffer.from(blobStatusReply.info.blob_header.commitment.x).toString("hex"),
                    y: Buffer.from(blobStatusReply.info.blob_header.commitment.y).toString("hex")
                },
                data_length: blobStatusReply.info.blob_header.data_length,
                blob_quorum_params: blobQuorumParams
            },
            blob_verification_proof: {
                batch_id: blobStatusReply.info.blob_verification_proof.batch_id,
                blob_index: blobStatusReply.info.blob_verification_proof.blob_index,
                batch_metadata: {
                    batch_header: {
                        batch_root: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.batch_metadata.batch_header.batch_root).toString("hex"),
                        quorum_numbers: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.batch_metadata.batch_header.quorum_numbers).toString("hex"),
                        quorum_signed_percentages: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.batch_metadata.batch_header.quorum_signed_percentages).toString("hex"),
                        reference_block_number: blobStatusReply.info.blob_verification_proof.batch_metadata.batch_header.reference_block_number
                    },
                    signatory_record_hash: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.batch_metadata.signatory_record_hash).toString("hex"),
                    fee: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.batch_metadata.fee).toString("hex"),
                    confirmation_block_number: blobStatusReply.info.blob_verification_proof.batch_metadata.confirmation_block_number,
                    batch_header_hash: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.batch_metadata.batch_header_hash).toString("hex")
                },
                inclusion_proof: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.inclusion_proof).toString("hex"),
                quorum_indexes: '0x' + Buffer.from(blobStatusReply.info.blob_verification_proof.quorum_indexes).toString("hex")
            }
        }
    };
}






