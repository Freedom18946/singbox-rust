/// 阻断出站：任何连接请求都返回错误。
#[derive(Clone, Debug)]
pub struct BlockOutbound {
    tag: sb_types::OutboundTag,
}

impl Default for BlockOutbound {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockOutbound {
    /// Create a new block outbound instance
    #[inline]
    pub fn new() -> Self {
        Self::with_tag("block")
    }

    /// Create a blocked outbound with its configured route tag.
    #[inline]
    pub fn with_tag(tag: impl Into<String>) -> Self {
        Self {
            tag: sb_types::OutboundTag::new(tag),
        }
    }
}

impl sb_types::Outbound for BlockOutbound {
    fn r#type(&self) -> &str {
        "block"
    }

    fn tag(&self) -> sb_types::OutboundTag {
        self.tag.clone()
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        &[sb_types::NetworkKind::Tcp, sb_types::NetworkKind::Udp]
    }

    fn dial<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::ports::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async {
            Err(sb_types::CoreError::policy(
                "blocked by configured block outbound",
            ))
        })
    }

    fn listen_packet<'a>(
        &'a self,
        _session: &'a sb_types::Session,
    ) -> sb_types::ports::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
    {
        Box::pin(async {
            Err(sb_types::CoreError::policy(
                "blocked by configured block outbound",
            ))
        })
    }
}
