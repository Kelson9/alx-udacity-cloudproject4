import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

import { verify} from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
const cert = `-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIJV2B2vuTeLeqsMA0GCSqGSIb3DQEBCwUAMCQxIjAgBgNV
BAMTGWRldi1mYTM1ajljaS51cy5hdXRoMC5jb20wHhcNMjIxMDA1MDMyOTIzWhcN
MzYwNjEzMDMyOTIzWjAkMSIwIAYDVQQDExlkZXYtZmEzNWo5Y2kudXMuYXV0aDAu
Y29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm4bfglpfD45URJsi
1gIRlqzcFp5IrSZ0CtRq9SVU7cOgeNjdJD04bCU/n5yGXamM7JwFsIwKMbO3edE5
tm7JQJjzuvWU4ph+5C5eNstgBu5V/oUojyPUnBS3smXloRTHAwnFOUZRrlVPh28i
4AFRpY9c2Gjgh6lOxzjndH9iXtvcfxfI9vbo5wbTg0QPyiMOb2WsSDpOJFPEmqFa
p7iYYmS2ucuKs98y5WlBpwcYsE2eHHvjbrDFcStXo7vJDJh2cb7WTsIWsK4YHpEX
jlt6Fe4TBS8FYDI/SOXJwYWjwz1EgqNy8W1u6gAgOYP3pner6CSqnMjYQoB9me/J
AuSF5QIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRBdSDW1Ndd
DhgEXSQ2ra/mcMuItDAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADggEB
AIf4QbVlTficK3A+u/ikEKlOtVBVPlts+OubX255XhVshF7uuKW5MdXUrFBBNx4C
uiSYIUMl6G9ayKdR54mOUTZELeFNJ2E5LLXlmk8IuUgoR5bAg5w7N0Mb1pURm1rj
CORo46JUiOhv6+e8AHw+Pc16QkcNuR1gyPhvXLBDzuRFeiHs8b8RqTkNK+PnB13E
WluvkoZdjm5BDPqwLmrEPPb1Bifxer/Cp5+BeOV/F+yuIvF+o9a20AMibbe45l5+
s4zCvGAmon8I1C57kipCmBtM4xyrYF7jtPyzVTi98IGSlwOO5azGdU1tPkXVWTNg
MzrfXTzo5OPSByDLbxPf6d4=
-----END CERTIFICATE-----`

export const handler = async (
  event: CustomAuthorizerEvent
): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  // TODO: Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
  
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
