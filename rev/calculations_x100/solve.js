function solve() {
    const socket = io();
    socket.on('connect', () => {
        socket.emit('start', () => {});
    });

    const MOD = BigInt(10**9 + 7);

	function invmod(a, m) {
		function xgcd(a, b) {
			a = BigInt(a);
			b = BigInt(b);
			if (b == 0) {
				return [1, 0, a];
			}
	
			temp = xgcd(b, a % b);
			x = temp[0];
			y = temp[1];
			d = temp[2];
			return [Number(y), Number(x-y*Math.floor(Number(a/b))), Number(d)];
		};

		return xgcd(a, m)[0]
	};

    function fac(n, k=1) {
        n = BigInt(n);
        let r = 1n;
        while (n > k) {
            r *= n;
            r %= MOD;
            n -= 1n;
        }
        return r;
    };

    function bincoef(n, k) {
        if (n < k){
            return 0;
        }

        n = Number(n);
        k = Number(k);
        k = Math.min(k, n-k);
        n = BigInt(n);
        k = BigInt(k);

        let res = BigInt((fac(n, n-k) * BigInt(invmod(fac(k), MOD))) % MOD);
        return Number((res + MOD) % MOD);
    }

    function solve_pow(a, b, c, d) {
		let val = a+b;
		let val2 = c*d + val;
        
		let res = BigInt(invmod(val2, MOD));
        while (res < 0) {
            res = (res+MOD) % MOD
        }
        
		res = (res * BigInt(val)) % MOD;
        while (res < 0) {
            res = (res+MOD) % MOD
        }

        res = (res * BigInt(bincoef(val2, d))) % MOD;
        while (res < 0) {
            res = (res+MOD) % MOD
        }

        return Number(res);
    };

    function solve_op(a, b, o) {
        switch(o) {
            case '+':
                return a+b;
            case '-':
                return a-b;
            case '*':
                return a*b;
            case '/':
                return Math.floor(a/b);
        }
    };

    socket.on('message', function(data) {
        console.log(data);
		if (data.type == 'message') {
			console.log(data.message);
			return;
		}

		let a = data.operation.a;
		let b = data.operation.b;
		let o = data.operation.o;
		let op_resp = solve_op(a, b, o);

		a = BigInt(data.pow.a);
		b = BigInt(data.pow.b);
		let c = BigInt(data.pow.c);
		let d = BigInt(data.pow.d);
		let pow_resp = Number(solve_pow(a, b, c, d));

		socket.send({
			'operation_response': op_resp,
			'pow_response': pow_resp,
		});
    });
}

solve();

// TeamItaly{who_knew_nintendo_games_have_ctf_flags_inside?_805810a8}
