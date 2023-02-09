// npm install jsonwebtoken
// npm install npm install @aws-crypto/client-node
// zip -r ../lambda-new-authorizer .
import {
    KmsKeyringNode,
    buildClient,
    CommitmentPolicy,
} from '@aws-crypto/client-node';

import jwt from 'jsonwebtoken';

const jwtKey = "my_secret_key";
var decrypt_token;
const { decrypt } = buildClient(
  CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
)
const generatorKeyId ='arn:aws:kms:us-east-2:884069944685:alias/kms-jwt'
const keyIds = [
    'arn:aws:kms:us-east-2:884069944685:key/0401e5b0-0fd0-4f68-b89d-7ed0a4b73418',
  ];
const keyring = new KmsKeyringNode({ generatorKeyId, keyIds });

const generatePolicy = ({ allow }) => {
  return {
      principalId: 'token',
      policyDocument: {
          Version: '2012-10-17',
          Statement: {
              Action: 'execute-api:Invoke',
              Effect: allow ? 'Allow' : 'Deny',
              Resource: '*',
          },
      },
  };
};

export const handler = async(event) => {
    console.log('*** Loading lambda new authorization Version 1.1');
    
    var tokenID =( event.headers && (event.headers['Authorization'] || event.headers['authorization'])) || event.authorizationToken;
    if(!tokenID){
        console.log('==> Token not found !!!');
        return generatePolicy({ allow: false });
    }
    tokenID = tokenID.replace(/^Bearer\s+/, "");

    console.log('----------------------');
    console.log('==> tokenID : ', tokenID);

    if (!tokenID) {
        console.log('==> Authorization token not sended');
        return generatePolicy({ allow: false });
    }
  
    if (event.headers['jwe'] == true){
        const encryptedBuffer = Buffer.from(tokenID, 'base64');
        const { plaintext } = await decrypt(keyring, encryptedBuffer);

        console.log('==> plaintext.toString : ', plaintext.toString('utf8'));
        tokenID = plaintext.toString('utf8');
    
        console.log('----------------------');
        console.log('==> tokenID_final : ', tokenID);
    }

    try {
        /*if (tokenID === 'cookie') {
          console.log('==> Autorizado !!! ');
          return generatePolicy({ allow: true });
        }*/
        jwt.verify(tokenID, jwtKey);
        console.log('==> Autorizado !!! ');
        return generatePolicy({ allow: true });
  } catch (error) {
        console.log('==> Nao Autorizado Error ', error);
        return generatePolicy({ allow: false });
  }
  
};
