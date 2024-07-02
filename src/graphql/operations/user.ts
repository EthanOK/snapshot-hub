import db from '../../helpers/mysql';
import { formatUser } from '../helpers';
import log from '../../helpers/log';
import { capture } from '@snapshot-labs/snapshot-sentry';
import { getAddress } from '@ethersproject/address';

export default async function (parent, args) {
  let id = args.id;
  try {
    id = getAddress(id);
  } catch (error) {
    return Promise.reject(new Error('invalid id'));
  }
  const query = `SELECT u.* FROM users u WHERE id = ? LIMIT 1`;
  try {
    const users = await db.queryAsync(query, id);
    if (users.length === 1) return formatUser(users[0]);
    return null;
  } catch (e: any) {
    log.error(`[graphql] user, ${JSON.stringify(e)}`);
    capture(e, { args });
    return Promise.reject(new Error('request failed'));
  }
}
