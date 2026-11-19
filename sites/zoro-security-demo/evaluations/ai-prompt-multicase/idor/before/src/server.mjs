import http from 'node:http';
const users={'Bearer trace-owner':'owner','Bearer trace-other':'other'};
export function createServer(){return http.createServer((req,res)=>{
 res.setHeader('content-type','application/json');const user=users[req.headers.authorization];
 if(req.url==='/api/me'){if(!user){res.writeHead(401).end('{}');return}res.end(JSON.stringify({id:user}));return}
 if(req.url==='/api/orders/demo'){res.end(JSON.stringify({orderId:'demo',ownerId:'owner',marker:'synthetic-order-owner-a'}));return}
 res.writeHead(404).end('{}');
})}
