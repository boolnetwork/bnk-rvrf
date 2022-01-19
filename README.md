# rvrf

### Ristretto

#### Use
```asciidoc
let rvrfproof = rvrf_prove(witness, statment.clone(), rr, crs, r, c, sks, l);
let res = rvrf_verify(rvrfproof, statment, crs, rr);
assert_eq!(res, true);
```

#### bench: 

rvrf 1-50 100 rounds

AMD Ryzen 7 1700 8C16T 3GHz / RAM16G   cpu10%

amount: amount of parties

avg time of prove/verify 

proof size

cargo test --package ringvrf --lib rvrf::tests::rvrf_bench_test
```
amount:1,prove:8.561775ms,verify:10.173717ms,size:1852
amount:2,prove:15.331368ms,verify:15.398094ms,size:2823
amount:3,prove:16.856327ms,verify:16.04815ms,size:2822
amount:4,prove:26.206117ms,verify:21.491472ms,size:3791
amount:5,prove:28.615034ms,verify:22.284686ms,size:3798
amount:6,prove:30.669864ms,verify:22.917963ms,size:3794
amount:7,prove:32.471231ms,verify:23.505247ms,size:3796
amount:8,prove:45.846618ms,verify:29.010783ms,size:4763
amount:9,prove:49.301904ms,verify:30.213376ms,size:4766
amount:10,prove:52.642745ms,verify:31.019657ms,size:4764
amount:11,prove:55.33269ms,verify:31.467656ms,size:4764
amount:12,prove:58.097531ms,verify:32.432598ms,size:4766
amount:13,prove:61.405956ms,verify:33.268342ms,size:4761
amount:14,prove:64.505633ms,verify:33.774218ms,size:4765
amount:15,prove:67.408452ms,verify:34.562784ms,size:4768
amount:16,prove:88.501454ms,verify:40.326344ms,size:5735
amount:17,prove:92.079138ms,verify:40.662841ms,size:5734
amount:18,prove:95.883303ms,verify:41.556435ms,size:5735
amount:19,prove:99.622586ms,verify:42.730064ms,size:5740
amount:20,prove:104.178639ms,verify:43.239976ms,size:5737
amount:21,prove:107.424767ms,verify:44.097763ms,size:5737
amount:22,prove:111.505793ms,verify:44.764466ms,size:5734
amount:23,prove:114.809973ms,verify:45.639442ms,size:5736
amount:24,prove:119.864544ms,verify:46.585655ms,size:5740
amount:25,prove:122.969222ms,verify:47.04676ms,size:5737
amount:26,prove:125.965616ms,verify:47.902884ms,size:5737
amount:27,prove:129.72785ms,verify:48.166483ms,size:5735
amount:28,prove:133.543142ms,verify:49.234757ms,size:5735
amount:29,prove:136.684277ms,verify:49.693669ms,size:5740
amount:30,prove:141.678736ms,verify:50.443063ms,size:5738
amount:31,prove:145.20328ms,verify:51.789587ms,size:5732
amount:32,prove:179.463532ms,verify:57.151422ms,size:6704
amount:33,prove:184.09287ms,verify:58.199179ms,size:6707
amount:34,prove:187.422113ms,verify:58.6709ms,size:6707
amount:35,prove:196.146751ms,verify:60.706421ms,size:6708
amount:36,prove:200.367416ms,verify:61.276688ms,size:6703
amount:37,prove:202.292068ms,verify:61.43887ms,size:6705
amount:38,prove:207.704677ms,verify:62.23879ms,size:6708
amount:39,prove:213.296976ms,verify:63.475378ms,size:6708
amount:40,prove:219.292527ms,verify:64.358197ms,size:6708
amount:41,prove:223.016185ms,verify:64.980372ms,size:6706
amount:42,prove:226.980941ms,verify:64.78528ms,size:6708
amount:43,prove:231.172533ms,verify:66.173595ms,size:6700
amount:44,prove:239.67294ms,verify:67.614288ms,size:6707
amount:45,prove:241.144324ms,verify:67.603849ms,size:6706
amount:46,prove:245.479856ms,verify:68.646706ms,size:6707
amount:47,prove:251.482986ms,verify:69.770301ms,size:6711
amount:48,prove:255.407263ms,verify:70.198165ms,size:6706
amount:49,prove:258.825655ms,verify:71.02966ms,size:6707
```
