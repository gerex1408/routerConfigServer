const express = require('express')
const app = express()
app.use(express.json());
var shell = require('shelljs');
const path = require('path');

app.use(express.static(path.join("/home/gerard/Desktop/RouterConfigWeb/client", 'build')));

const ROUTER_PASSWORD = "password" //AIXÒ NO ÉS FA ! S'HA DE TROBAR LA MANERA DE FER-HO BÉ
let XARXA_CONFIGURABLE = ""
let PREFIX_XARXA  = ""

const jwt = require('jsonwebtoken')

const  netmask2CIDR = (netmask) => {return (netmask.split('.').map(Number).map(part => (part >>> 0).toString(2)).join('')).split('1').length -1}

const verifyJWT = (req,res,next)=>{
    const token = req.headers["x-access-token"]

    if(!token){
        res.status(401).send("You have no token")
    }
    else{
        jwt.verify(token,"jwtSecret",(err,decoded)=>{
            if (err){
                res.status(401).json({auth:false, message:"Failed to authenticate"})
            }
            else{
                req.id = decoded.id;
                next();
            }
        })
    }
}

//LOGIN ENDPOINT

app.post("/login",(req,res)=>{
    const password = req.body.password
    if(password===ROUTER_PASSWORD){
        const id = 0
        const token = jwt.sign({id},"jwtSecret",{
            expiresIn: 3600
        })
        res.json({auth: true, token: token})
    }
    else{
        res.status(403).send('Wrong Password');
    }

})

//ENDPOINTS DE CONFIGURACIÓ
app.get("/dhcp",verifyJWT,(req,res)=>{
    const { stdout, stderr, code } = shell.exec('sshpass -p xarxes ssh xarxes@8.0.2.1;cat ~/etc/dhcp/dhcpd.conf | grep subnet;cat ~/etc/dhcp/dhcpd.conf | grep range', { silent: true })
    if(code===0){
        const stdoutArray = stdout.split(" ")
        const ipXarxa = stdoutArray[1]
        XARXA_CONFIGURABLE = ipXarxa
        const mask = stdoutArray[3]
        PREFIX_XARXA = netmask2CIDR(mask)
        const iniciRang = stdoutArray[5]
        const finalRang = stdoutArray[6].replace(/(\r\n|\n|\r)/gm, "").replace(";","")
        const obj = {
            ip:ipXarxa,
            mask:mask,
            inici:iniciRang,
            final:finalRang
        }
        res.send(obj)
    }
    else{
        res.status(409).send("Not able to get the config data")
    }
    
})

app.post("/dhcp",verifyJWT,(req,res)=>{ //POTSER S'HAURIEN D'ELIMINAR LES IP TABLES ?
    const ip = req.body.ip
    const mask = req.body.mask
    const inici = req.body.inici
    const final = req.body.final
    const contingutFitxerConfig = "ddns-update-style none;\noption domain-name 'example.org';\noption domain-name-servers ns1.example.org, ns2.example.org;\ndefault-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nlog-facility local7;\nsubnet "+ip+" netmask "+mask+" {\n\trange "+inici+" "+final+";\n\toption routers 8.0.1.1;\n}"
    /*if (shell.exec('ssh xarxes@8.0.2.1;echo '+contingutFitxerConfig+' > /etc/dhcp/dhcpd.conf',{silent:true}).code !== 0){
        res.status(409).send("Not able to execute the configuration command")
    }*/
    if (shell.exec('sshpass -p xarxes ssh xarxes@8.0.2.1;echo "'+contingutFitxerConfig+'" > ~/etc/dhcp/dhcpd.conf',{silent:true}).code !== 0){
        res.status(409).send("Not able to execute the configuration command")
    }
    else{
        res.send("Config succesfull")
    }
})

app.get("/ipTables",verifyJWT,(req,res)=>{
    const { stdout, stderr, code } = shell.exec('sshpass -p xarxes ssh xarxes@8.0.2.1;sudo iptables -t nat -L -v -n | grep SNAT', { silent: true })
    if(code===0){
        let stdoutArray = stdout.split("\n")
        stdoutArray.pop
        res.send({entrades:stdoutArray})
    }
    else {
        res.status(409).send("Not able to get the config data")
    }
})

app.post("/ipTables",verifyJWT,(req,res)=>{
    const origen = req.body.origen
    const desti = req.body.desti
    const interficie = req.body.interficie   //destí no té /xx
    if (shell.exec('sshpass -p xarxes ssh xarxes@8.0.2.1;sudo iptables -t nat -A POSTROUTING -s ' +origen+'-o '+interficie+' -j SNAT --to-source '+desti,{silent:true}).code !== 0){
        res.status(409).send("Not able to execute the configuration command")
    }
    else{
        res.send("Config succesfull")
    }
})

app.delete("/ipTables",verifyJWT,(req,res)=>{
    if (shell.exec('sshpass -p xarxes ssh xarxes@8.0.2.1;sudo iptables -t nat -F',{silent:true}).code !== 0){
        res.status(409).send("Not able to execute the configuration command")
    }
    else{
        res.send("Config succesfull")
    }
})

app.get("/forwarding",verifyJWT,(req,res)=>{
    const { stdout, stderr, code } = shell.exec('sshpass -p xarxes ssh xarxes@8.0.2.1;sysctl net.ipv4.ip_forward', { silent: true })
    if(code===0){
        const state = stdout.split(" = ")[1].replace(/(\r\n|\n|\r)/gm, "")
        res.send({state:state})
    }
    else{
        res.status(409).send("Not able to get the config data") 
    }
})

app.post("/forwarding",verifyJWT,(req,res)=>{
    if (shell.exec('sshpass -p xarxes ssh xarxes@8.0.2.1;sudo sysctl net.ipv4.ip_forward='+req.body.state,{silent:true}).code !== 0){
        res.status(409).send("Not able to execute the configuration command")
    }
    else{
        res.send("Config succesfull")
    }
})


app.get('*', (req,res) => {
    res.sendFile(path.join("/home/gerard/Desktop/RouterConfigWeb/client", 'build/index.html'));
});


app.listen(5000, ()=>{console.log("server started on port 5000")})