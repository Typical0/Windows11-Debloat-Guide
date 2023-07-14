<# :
@echo off &chcp 850 >nul &pushd "%~dp0"
@set "0=%~f0" &powershell -nop -c $f=[IO.File]::ReadAllText($env:0)-split':bat2file\:.*';iex($f[1]); X(1)

fltmc >nul 2>&1 || (
    powershell Start-Process -FilePath "%0" -ArgumentList "%cd% %*" -verb runas >NUL 2>&1
    exit /b
)

cd /d %1
set "psScript=%~f0" & powershell -nop -c "Get-Content """$env:psScript""" -Raw | iex" & exit /b

:bat2file: Compressed2TXT v6.5
$k='.,;{-}[+](/)_|^=?O123456A789BCDEFGHYIeJKLMoN0PQRSTyUWXVZabcdfghijklmnpqrvstuwxz!@#$&~'; Add-Type -Ty @'
using System.IO; public class BAT85 {public static void Dec (ref string[] f, int x, string fo, string key) { unchecked {
byte[] b85=new byte[256];long n=0;int p=0,q=0,c=255,z=f[x].Length; while (c>0) b85[c--]=85; while (c<85) b85[key[c]]=(byte)c++;
int[] p85={52200625,614125,7225,85,1}; using (FileStream o=new FileStream(fo,FileMode.Create)) { for (int i=0;i != z;i++) {
c=b85[f[x][i]]; if (c==85) continue; n += c * p85[p++]; if (p==5) {p=0; q=4; while (q > 0) {q--; o.WriteByte((byte)(n>>8*q));}
n=0;}} if (p>0) {for (int i=0;i<5-p;i++) {n += 84 * p85[p+i];} q=4; while (q>(5-p)) {o.WriteByte((byte)(n>>8*(--q)));} } } }}}
'@; cd -Lit($env:__CD__); function X([int]$x=1){[BAT85]::Dec([ref]$f,$x+1,$x,$k); expand -R $x -F:* . | Out-Null; del $x -force}

:bat2file:[ Echnobas-CommonSense-Antivirus-Package31bf3856ad364e35amd641_0_0_3_cab
::AveYo.....2@cr@.....^_;a0......$}I}.99(,xMO(]o]kuQ.99(,bQw=8.......]|gahsR[57W,oYmw_#^QQJxY^Z8sFy~T;^QB6#Gw/1OeiU_OE7Q+fG2VtTEX|YW
::O]duT?K-+{?J#UZFOb6.^rnx1^v)/vE7G1t|N;TS}cP[Y8jZ,y...,h{1?}/....n.........{.9I=[..IA|4PE(;......,f_z{1?}o;42i+........,(.99(;..([t
::.##9{......ATBl0GYxFI/IH.F0|rGY;jkK..;Tw.....t;ygY/A4R[F5ATt^x6B1._dMI.]e,[...;f9s|G[./GhUOYnlkGu5L,JG3DKFy)NtF5fm3e+oG6Gt+gf?JPDP
::?K540E7X^R?rFL;Dys0u^vJgG=M3-mYM$I+Dyu3{Eu4};FO3~.?K-1K?J1PSYM9fze(-Y(.##CE-oKM^.ATBl0GYx_Y|JQfDyl?QEW@JT?rMW+FxJNOE4{OyOn{9=F5cMT
::O|dQ[?r}L[=p1oR??]quEX|YWO]duT?K-+{?J#0#?)+BB1F(.9=QMgAYLw=3OhdfQ1}kCWOYL{JOn_8NY||9#FxD-(.Ays!Z&A#G}szB7B(wwcG)3_H}=0]X,-bA14@}5|
::kvY}Z.LAFr,cPYg[VTE_.l~e|QEm3@FojoLZt3&sc9nsQ[VtNqV_i1cKW0)ODxYwsZ5m4|PxYu1_xhb$woF/MZ&Kw0eC${ay)8-]x].0grcS[v.iNt2}|Qb,9U)MV;d3a-
::R&Vl,9Q@[CyS9T!hmhX^BB}ipH]-G)mPghnLa6Em-(.6vR7K4.4EpLtJX~01d?F=)E-8tH?4.OT^{!7j]Qr)!BFUUsiRl|.Vg+PDXT6A^]Q[$9n_?|_TcgOjG6N^I|gf~?
::TG!K(^6LX=Igbiwc9ndViZv0,_W$]+H^w9rhEfPVh)3u;eC&VhSoD;!;f.cfi?NdPBM^Q5}=/knW)A^99^dv]1Z@k&izM7s+^tQDIlw-c1+x&rbu1}qEy?mF8Y_P7}OZvs
::4$!~Rn,v=V87~,B=154doKO(b9Wp)X4B8p)oUJW(^5~/6P|QzgT_5[Z{3Hx;LNorEWZxK7pf2T1bzdCPa.9M2}0t&;pl4~B-cZE?;ymfJ}|UeJov3KMPg/iroK}+;N3-$E
::ozGp??sN=2FCt-,ZEm5UP,GDL@|rNvUc]hR3!8!otbMf,Ys;aEmR}hgi^)C5hZ+hw8=$VJi/rj8GVjpL;m$!j^AruvQnt+-)Q5+V).gkh09aZyT6C!],RFvQ-MoPgoYp[q
::.[xv}[EqP7FKLHY|1~gc,~0ew8[,7qM_{TE?xiYkC,Qq33#&AH_L0!evhw!JYzMRsC^KXFuOKL]LVpLi[7^@Oh-6;M{rAuAv{Aq#x@gB?BH/e]?^QBWi1{tRyRbf[p6iF3
::@VVjza,)RECDn]^uv=A33@+#/}NIRhR^|EKJaUHh[La,7Bx|U+JGU/tHmE191{!Pn;;j4TK@9ZwGl{)GBqv=.sz}I46}~~2UbMs)Mi)F5d;G}tEIJXUvXtYUU[e86r+}6_
::iy7-/{kecZIe-I&CraIJlv=pO(@1[4[|)7~bj?)06d8&D(VE)RlJE(k4C/-=LEmHl7V&?d2xoNITI1w436R+!9_b5ay;fpZPLMwG}J|vb{Lh+yl)!Ec-$6MOg|.0~?=}/h
::Jh__V]l6v8c7Gx6)|c1W]$j+TiTcPjwx#]{}SN=ot^wuM0/U7o([spb1M=a=QCC4_;1fq~al;@@=X?mC((UiVIb$h1/RR4?mNdemqb2J)14jskmJ7;)Z!6S&C;X(egpzh8
::4B_BhG@M+HcK!QhS.EWTo?!EX{S&PasTyWf1llM+)h|1HDlhBg@}pGG.(Lqp}5HdOMO8=U.D=}c.}rvZWy6KLcLI1HJ;_VWb$+tH(SN2-yG&W!q&seWn{txm}kI&y@&FEM
::yEsZ3z2_s{!N#^_5pQS}8bj3epQ7sP?@hZzM,{_TcB4ibg+|2?rx__jIV;ydL(5@3q]t6-Z2&FbF3cuZ!#4/&Z2t.Q_k7OFSE+bqt}n7kOrqV8s7JeAX4oEeYMZy?Br7Ff
::7.i2YV4}5L!DpIafwA|$=gy9jh)9#P@MCvQ1zEUWY?Y}mmFT;U$+SC4/U|mSR+~AQczX4kyi?|#.aZPlj^0RqbnW8Fl-UF_k1})p5f!#887|+5J?ZF5p)y~@M}#6wZ=ax_
::U,Zvj5@dhq9)@c{laBhp.D3Is@}blS-n0}YzWdXqTiJ;VX1|iXKZgv_HLfh+E0BFI)zo#jSQ+y~(=C{yrO$J=M!yfrthZor?yt[rkw#;w46EogQE++gT~)$nvRjv2l2Rp7
::,Z,[V4W3TTnt{Rm0XLueP|LmFW20YHS6spc7eW(edQBBfc0f]5P[cyhD5As,|C60[)G&#cWF,PPizgX2wP~lby4q6wKLDyYk_w2~T}C_3(@bwFxJY$yc[b_zwRmz0Sc}7@
::7_9JM{=@;zalo+zf27;dUf,[&[~2=CZ_&pAcZW2xugALXze!/CRHldG)zPA{cdHyzZ/a)-{6/hSZlF~ZD(Q)}-s;xk)SL_BiNCR!5$nsUiT#0b8=HmztalcAe7gm^z=(Jx
::lnp)pSz=E@3xHV!wX;qJK0aMa=3y$Ft;.l.8pHKz|u^mm;d-w+ul~)[ub4.)PZnrLmSi;wgBRr8bBAMmgIwjPcSD6u2gQjbfBN(0[4LS=bNlmXgNE-7IHkR}1J1rohtnQJ
::0}d721+|(b/Y#!9ff_HkEtXjr9!m;2sqbE}NM1S$L-It4?D9/tmr5cHJUIMN9f8V8I.0,LIaQ9~EO7^8@eNY@wAr_durg0]Z{?7HPGl_9g7FE?U(&UAa(X]gI8Y.pWCe!k
::{vEdT6Lnri97AFmwL?#,AM+~!t0E&n75mc=e]$4g?tZIo(}I{#tdw{tF2Yr)h@y)Uf89,O@sIJ3)d6uh2wuy!aeg}jx7QK(_;5@2FDl@4@#3wST&5Y,vVK-eo6[OzCxWis
::xhbIStf)VHTI&C(G)lVD=tP;P9odXE[5y)dd7~7ivz0)u8Fp]f_/Jar3#LEpqa1l#ZwYm?me(EMrf8PDJCrw5+7G[/mBqV-Z!pHtP3R@Vr-D,5p3pwD/;q6nvre;,))8B~
::/I.F__c!6,ehFIdY4If&,x@D[P.-yie!N/5MgW[Uq=PxnC=n{ZvQ-oaM(h/$A3$Y?j)|6hAaCd1Jr-i[CdoZ=5,08&Nth/TGyzX+z+.WiCeDHAE!sS1mtsjPsM[|kWe?ik
::Ie4@85](cmW2ifIZHZ$R=v7PlR/~M.}p4JOmz36IR)N15J)q~kP{9PDzA3MV;+yf9.}JZZt@si8EN^X97-qzfGs_ZaJ{0x=5{I=KTy4dWndQtkF7~;N0eY0nVgo#]XhXdV
::YMWgWx-RK!j0fpsA@.MbBpit!^h1UFmS-@aab40CgR0FOQ51)o|MH49Vx#)&@PfQb,L;}v|6c}8+hSG(W000~Vh6WPlft15A0Q|!R~Ay5.ExL6ZkaLg9l_Cq8Y;kdh2iDS
::;jE@$VV^10$^xFEpY2i}q!f_}75y.]IXMF8KUrgC7i0gs#Z?I1;6LeN|agoo!H|_|.rk)0,~+V4.VvG[=k3#L,!xcu6_(A+,AMU_.}^&!,!~sk.9ieUObj.hUTv/VMX~1h
::,!~sk.9ieUObj,,Ur;7&XT8=^c-yjVZ!+QAq3fTu,Crrq=MId9|qD,V.M141,UgC-,9ioBHL[AlenunH6mV2=Q(4YIXgu[-L6#y7[Cvieg+8&S=ed1wE,@OSFKP}7.9vK/
::/TLRI?W/;jF4B$ox~c4qect|#Hx#.Vo-HJq54CgJF,dYX+kqQI[MR/D#?e)x.9P94?IIi##sR7w46)4Se-MSU=ed1w|agoo!H|_+{Q{0jI-@hy;wNo1,Az0E9Y&Wl=J/ot
::99PTA{9NaVGRYD$eYu-Q}O2T~,[;L^{sUcFF6S5}FO))b(.SNe,7CRRAtn(ZYpfv^e9I@rIlC#8E9D2-YY9-i+g7+G,AU}IAtn(ZYpfv^e9ea.YLmc=e,ngS-3ogxOhc(Y
::=MkZH?otX/?)?LE=nk7B=nkeH?)P^qI-@hy;wNo1,Az0E9Y&Wl=J/ot99PTA{9NaVGRYD$eYu-Q}O2T~,[;L^{sUcFF6S5}FO))b(.SNe,7CRRAtn(ZYpfv^e9I@rIlC#8
::E9D2-YY9-i+g7+G,AU}IAtn(ZYpfv^e9ea.YLmc=e,v?K/&$K?;@Hc;NF])Z.9ID+,/qQj.}=.({1Jnc.9G=f3$f/+Qb^CE^]imr8R4LJUC^smhq?.XU[[Wtf)2Q13D)kp
::ZbR==Xg!ig3p,?-}M@M!pwbgKY(W0nY1EDlyqNT897W4sW78AQL=iL_8|madilLPq!vRDaVrl33iH&}69AI[SLId_K6MM3LKEw;$j^=|;,Bt[7;@H@qISthiY|-0rEd5#$
::{&x+);;?o-Vv/t&S9B)oYCX+(CFcJ?TC+Gw/]{?zSS;;NK=Qr&UZSmF]Oh0sp@~#U;ibrd#)YjBZ(a1xZ^u63apZd;TNt.?Uj.lE{{h__(-A8~lnMz-};q2{?w]{$Nk,CN
::@U=gEPFEV9Bq6;?.99|@Ma&OSWkIt!,[{Dp,8vq|,!~sk.9ieUOcUVt,!lgi.9vV1.$73X,!5sJ}KtpgA8J_35tuyN|qD]W,7JtqAtn(ZYpfv^e9e|@FykmwF=BbnFUY2{
::GuEw?/FDomGuwz$=k~JV,!5s|,XXC;?_-9S1El$E=MRNI=KHD,9DORR+[JC~50J8lTwusUY^YvuO,?VpadCsK{sKp4(C6Jy##iGV.}/vm;@Hc;NF])Z.Bo}O,/qQy.^^~q
::?Le(Im8|mHh.WcdAW-,QR_aF1]GOMFnNj^px/{]1kHrhFV/lU7hT!VLh~/p#(uqs$;bva)(TF(E8GBObhh(W|BkKr)+ul,(#wG,?BzaP#1oRC9-RHTJB}wgA,d}+]L3p2L
::I4qp+QcAdHI(_ez!$meqvrg5Gw)ar9)q6Wf_ZHVMthx}YC@#VCFLvL-1X)]/EKM@-#/4DnpJ/k&R^nnG|Ow[{i}n/RVl/)xek{0p|2~7gHz;B#YqC&t/@,dmk;BY!^/Wwq
::d!1kr?wr^dy(rQ1@v,qToxO_h=e@T?n+que#)fOqOMh4-^bx1DpH!~&FO^b8^rrta|oUXQ=y/wOI-@hy;wNo1,Az0E9Y&Wl=J/ot99PTA{9NaVGRYD$eYu-Q}O2T~,[;L^
::{sUcFF6S5}FO))b(.SNe,7CRRAtn(ZYpfv^e9I@rIlC#8E9D2-YY9-i+g7+G,AU}IAtn(ZYpfv^e9ea.YLmc=I#ux^(QOeCcwc]c=8vV_6P#/p-=m)KN|YCX.$Fb/,Ua1H
::=J,I@|qD,V.M141.BWcj=I9mI,!ul468DsM.B6vh{sL-r,!,v_Mv9i1,CHp,{5l8f,Ae(3.Vibi-Ry7@{5l8f,Ae(3.Vj;v=(Xh2N|L[x-=4k9=m4iH8Hc.GDNs1j=@#|R
::koXhA)as!m8^f.}@}..QmiW}!=ed1w|agoo!H|_+.9vK/MlRsBt&s;Fh{A~Do30=U|qX_KOkFab}Z_iatNw?i[$0xupIv}J/_FZ@w.R8Jsr;pfI}uDEU5qARjM;_S5/S;2
::43|JLpNoP(4^g6ZY!Ec4cKf2bdQNO9QfWFkG,GyFY/8x.),[3p]#u1sis8}gY83$JSUS&HQ!u3}p(|5ayHX|2C6bW_BIrG3#3PSL8^cLyXU?PY$](fdh284-Uar3MWvy&n
::jAdN0p^]Twt1;AE^FHP.yjWuC1rP]rJhW96R5D/).fTqr_}]i^f7NH}h{kyMjft}B0g;C__}-k$|Q@f7p~Suu{/oaI-t.QcC.I2CwkRDKKarTC........
:bat2file:]
: #>

$cabPath = ".\Echnobas-CommonSense-Antivirus-Package31bf3856ad364e35amd641.0.0.3.cab"
$certRegPath = "HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates"

$cert = (Get-AuthenticodeSignature $cabPath).SignerCertificate
$certPath = [System.IO.Path]::GetTempFileName()
[System.IO.File]::WriteAllBytes($certPath, $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
Import-Certificate $certPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Copy-Item -Path "$certRegPath\$($cert.Thumbprint)" "$certRegPath\8A334AA8052DD244A647306A76B8178FA215F344" -Force  | Out-Null
Add-WindowsPackage -Online -NoRestart -PackagePath $cabPath | Out-Null
Get-ChildItem "Cert:\LocalMachine\Root\$($cert.Thumbprint)" | Remove-Item
Remove-Item "$certRegPath\8A334AA8052DD244A647306A76B8178FA215F344" -Force -Recurse | Out-Null
Remove-Item $cabPath -Force | Out-Null
Write-Host "Restart pending"
pause
shutdown /r /t 0