package org.logstash.beats;

import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.ssl.SslHandler;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.handler.timeout.IdleState;
import io.netty.handler.timeout.IdleStateEvent;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;

import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;

public class BeatsHandler extends SimpleChannelInboundHandler<Batch> {
    private final static Logger logger = LogManager.getLogger(BeatsHandler.class);
    private final AtomicBoolean processing = new AtomicBoolean(false);
    private String peerDnField;
    private String peerDn = null;
    private SslHandler sslHandler;
    private final IMessageListener messageListener;
    private ChannelHandlerContext context;


    public BeatsHandler(IMessageListener listener) {
        messageListener = listener;
    }

    public BeatsHandler(IMessageListener listener, String peerDnField, SslHandler handler) {
        messageListener = listener;
	this.peerDnField = peerDnField;
	sslHandler = handler;
    }

    @Override
    public void handlerAdded(ChannelHandlerContext ctx) throws Exception {
        context = ctx;
        messageListener.onNewConnection(ctx);
    }

    @Override
    public void handlerRemoved(ChannelHandlerContext ctx) throws Exception {
        messageListener.onConnectionClose(ctx);
    }

    @Override
    public void channelRead0(ChannelHandlerContext ctx, Batch batch) throws Exception {
        logger.debug("Received a new payload");

        processing.compareAndSet(false, true);

        for(Message message : batch.getMessages()) {
            if(logger.isDebugEnabled()) {
                logger.debug("Sending a new message for the listener, sequence: " + message.getSequence());
            }
            if (peerDnField != null) {
                java.util.Map data = message.getData();
                // If the peer has a DN, include that
                // Otherwise, set the field to be blank
                data.put(peerDnField, peerDn);
            }
            messageListener.onNewMessage(ctx, message);

            if(needAck(message)) {
                ack(ctx, message);
            }
        }
        ctx.flush();
        processing.compareAndSet(true, false);

    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        messageListener.onException(ctx, cause);
        logger.error("Exception: " + cause.getMessage());
        ctx.close();
    }

    @Override
    public void userEventTriggered(ChannelHandlerContext ctx, Object event) {
        if(event instanceof IdleStateEvent) {
            IdleStateEvent e = (IdleStateEvent) event;

            if(e.state() == IdleState.WRITER_IDLE) {
                sendKeepAlive();
            } else if(e.state() == IdleState.READER_IDLE) {
                clientTimeout();
            }
        } else if(sslHandler != null && event instanceof SslHandshakeCompletionEvent) {
            try {
                peerDn = sslHandler.engine().getSession().getPeerPrincipal().toString();
                logger.info("Got peer DN '" + peerDn + "'");
            } catch (SSLPeerUnverifiedException e) {
                peerDn = "";
            }
        }
    }

    private boolean needAck(Message message) {
        return message.getSequence() == message.getBatch().getBatchSize();
    }

    private void ack(ChannelHandlerContext ctx, Message message) {
        writeAck(ctx, message.getBatch().getProtocol(), message.getSequence());
    }

    private void writeAck(ChannelHandlerContext ctx, byte protocol, int sequence) {
        ctx.write(new Ack(protocol, sequence));
    }

    private void clientTimeout() {
        if(!processing.get()) {
            logger.debug("Client Timeout");
            this.context.close();
        }
    }

    private void sendKeepAlive() {
        // If we are actually blocked on processing
        // we can send a keep alive.
        if(processing.get()) {
            writeAck(context, Protocol.VERSION_2, 0);
        }
    }
}