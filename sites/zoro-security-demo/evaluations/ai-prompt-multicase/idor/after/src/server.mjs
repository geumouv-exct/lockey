import http from 'node:http';
const users={'Bearer trace-owner':'owner','Bearer trace-other':'other'};
const demoOrder = { orderId: 'demo', ownerId: 'owner', marker: 'synthetic-order-owner-a' };
export function createServer(){return http.createServer((req,res)=>{
 res.setHeader('content-type','application/json');
 const authorization = req.headers.authorization;
 const user = Object.hasOwn(users, authorization) ? users[authorization] : undefined;
 if(req.url==='/api/me'){if(!user){res.writeHead(401).end('{}');return}res.end(JSON.stringify({id:user}));return}
 if (req.url === '/api/orders/demo') {
  if (!user) {
   res.writeHead(401).end('{}');
   return;
  }
  if (user !== demoOrder.ownerId) {
   res.writeHead(403).end('{}');
   return;
  }
  res.end(JSON.stringify(demoOrder));
  return;
 }
 res.writeHead(404).end('{}');
})}
