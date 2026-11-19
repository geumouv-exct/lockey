import {randomUUID} from 'node:crypto';

// Keep individual HTTP requests shorter than the public proxy's timeout.
export function createNewsSearchJobs(load, waitMs = 15_000) {
  const jobs = new Map();
  return async function read(input) {
    const now = Date.now();
    for (const [id, job] of jobs) {
      if (job.expires <= now) jobs.delete(id);
    }
    let id = input.searchId;
    if (id === undefined) {
      if (jobs.size >= 64) throw Error('진행 중인 뉴스 검색이 많아요. 잠시 후 다시 시도해 주세요.');
      id = randomUUID();
      const job = {expires:Infinity};
      job.result = Promise.resolve().then(() => load(input)).then(data => ({status:200,data}), error => ({
        status:400,data:{error:error.message}
      })).finally(() => { job.expires = Date.now() + 120_000; });
      jobs.set(id,job);
    }
    const job = jobs.get(id);
    if (!job) throw Error('뉴스 검색이 만료됐어요. 다시 검색해 주세요.');
    let timer;
    try {
      const result = await Promise.race([job.result,new Promise(resolve => {
        timer = setTimeout(() => resolve({status:202,data:{searchId:id}}),waitMs);
      })]);
      if (result.status !== 202) jobs.delete(id);
      return result;
    } finally {
      clearTimeout(timer);
    }
  };
}
