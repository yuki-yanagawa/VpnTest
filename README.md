# VpnTest
① ping テスト socket rawでうまくいっていない => socket rawは複製し、1部をアプリケーション、1部をカーネルで操作するため、カーネルの制御が必要なのか？調査が必要。

rootユーザで
echo 1 > /proc/sys/net/ipv4/ip_forward
の設定をすれば NIC間でのIPフォワードが可能になる

sysctl -a

net.ipv4.ip_forward = 0 を 1に変更すれば良い

