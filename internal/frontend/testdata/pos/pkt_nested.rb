require "bpf"

Proto = BPF::ArrayMap.new("Proto", :u64, 256)
Port = BPF::ArrayMap.new("Port", :u32, 4)
Seen = BPF::ArrayMap.new("Seen", :u32, 2)


def ipv4(ctx)
  eth = ctx.check(0, 14)
  if eth
    if eth.be16(12) == 0x0800
      ip = ctx.check(14, 20)
      if ip
        ihl = ip.u8(0) & 0x0F
        if ihl >= 5
          Proto.atomic_add(ip.u8(9), 1)
          l4 = ctx.check(14 + ihl * 4, 4)
          if l4
            Port.update(0, l4.be16(2))
            p = Seen.lookup(0)
            if p
              Port.update(1, ip.u8(9) + eth.u8(13) + (p.load & 0xFFFF))
            end
          end
        else
          Port.update(3, ihl)
        end
      end
    end
  end
  BPF::XDP_PASS
end
BPF.xdp :ipv4
