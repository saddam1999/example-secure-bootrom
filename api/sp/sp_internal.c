/******************************************************************************
 *
 * Secure BootRom (SBR)
 *
 ******************************************************************************
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 ******************************************************************************/

/**
 * @file sp_internal.c
 * @brief
 *
 * @copyright Copyright (c) 2020 SiFive, Inc
 * @copyright SPDX-License-Identifier: MIT
 */


/** Global includes */
#include <string.h>
#include <stddef.h>
#include <common.h>
#include <errors.h>
#include <otp_mapping.h>
#include <metal/gpio.h>
/** Other includes */
#include <api/scl_api.h>
#if defined(HCA_HAS_SHA)
#include <api/hardware/scl_hca.h>
#else
#include <api/software/scl_soft.h>
#endif /* HCA_HAS_SHA */

#include <api/hash/sha.h>
#include <api/asymmetric/ecc/ecc.h>
#include <api/asymmetric/ecc/ecdsa.h>
#include <scl/scl_ecdsa.h>
#include <km.h>
#include <sbrm_internal.h>
#include <sbrm.h>
#include <sp.h>
#include <sp_internal.h>

/** External declarations */
extern t_context context;
extern char __sbrm_free_start_addr;
extern char __sbrm_free_end_addr;
/** Local declarations */
__attribute__((section(".bss"))) t_sp_context sp_context;
/** Array for key buffer
* Size is Old CSK descriptor + Old CSK size max + CSK Descriptor + CSK size Max + CSK sign size max */
__attribute__((section(".bss"))) uint8_t work_buf[M_WHOIS_MAX(C_KM_KEY_BUFFER_MAX_SIZE, sizeof(t_cmd_csk))];


/** UART **********************************************************************/
void sp_uart_isr(int32_t id, void *data)
{
	uint32_t									isr = sp_context.port.uart.reg_uart->ip & sp_context.port.uart.reg_uart->ie;

	/** Check if it's RX interruption */
	if( isr & C_UART_IP_RXWM_MASK )
	{
		/** Treat RX */
		sp_uart_rx_isr(id, data);
	}
	/** Check if it's TX interruption */
	if( isr & C_UART_IP_TXWM_MASK )
	{
		/** Treat TX */
		sp_uart_tx_isr(id, data);
	}
	/** We're done */
	return;
}
/******************************************************************************/
void sp_uart_rx_isr(int32_t id, void *data)
{
	register uint32_t									tmp_rx;

	/** Be sure to receive what is expected */
	while( sp_context.rx_communication.lasting )
	{
		tmp_rx = sp_context.port.uart.reg_uart->rx;
		/** Check if data remains */
		if( tmp_rx & C_UART_RXDATA_EMPTY_MASK )
		{
			/** Nothing more in FIFO */
			break;
		}
		else
		{
			/** Get data */
			sp_context.rx_communication.p_data[sp_context.rx_communication.received++] = (uint8_t)tmp_rx;
			/** Update lasting counter */
			sp_context.rx_communication.lasting--;
		}
	}
	/** Mask interruption */
	M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
	/** Remove threshold value */
	sp_context.port.uart.reg_uart->rx_ctrl &= ~C_UART_RXCTRL_RXCNT_MASK;
	/** Recompute threshold */
	if( !sp_context.rx_communication.lasting )
	{
		/** Put threshold to its maximum value */
		sp_context.port.uart.reg_uart->rx_ctrl |= ( ( ( C_UART_DATA_MAX_THRESHOLD_RX - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
	}
	else if( C_UART_DATA_MAX_THRESHOLD_RX > sp_context.rx_communication.lasting )
	{
		sp_context.port.uart.reg_uart->rx_ctrl |= ( ( ( sp_context.rx_communication.lasting - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
	}
	else
	{
		sp_context.port.uart.reg_uart->rx_ctrl |= ( ( ( C_UART_DATA_MAX_THRESHOLD_RX - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
	}
	/** Unmask interruption */
	M_UART_UNMASK_RX_IRQ(sp_context.port.uart.reg_uart);
	/** End Of Function */
	return;
}

/******************************************************************************/
void sp_uart_tx_isr(int32_t id, void *data)
{
	/** Mask interruption */
	M_UART_MASK_TX_IRQ(sp_context.port.uart.reg_uart);
	/** Interruption occurred therefore watermark has been triggered */
	if( sp_context.tx_communication.lasting )
	{
		/** Load data into TX FIFO */
		while( sp_context.tx_communication.lasting && !( sp_context.port.uart.reg_uart->tx & C_UART_TXDATA_FULL_MASK ) )
		{
			/**  */
			sp_context.port.uart.reg_uart->tx = *sp_context.tx_communication.p_data;
			sp_context.tx_communication.p_data++;
			sp_context.tx_communication.lasting--;
			sp_context.tx_communication.transmitted++;
		}
		/** Unmask interruption */
		M_UART_UNMASK_TX_IRQ(sp_context.port.uart.reg_uart);
	}
	else
	{
		/** Indicate transmitting is done  */
		sp_context.tx_communication.sent = TRUE;
	}
	/** End Of Function */
	return;
}

/******************************************************************************/
int_pltfrm sp_uart_receive_buffer(t_context *p_ctx, uint8_t *p_data, uint32_t *p_size)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint32_t									loop;
	uint32_t									i;
	volatile t_sbrm_context						*p_sbrm_ctx;

	/** Check input pointer */
	if( !p_data || !p_ctx || !p_size )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !*p_size )
	{
		/** Input size is null */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Get SBRM context to have CPU info */
		p_sbrm_ctx = (volatile t_sbrm_context*)p_ctx->p_sbrm_context;
		/** First check if there's data in dummy buffer */
		/** No data received in the meantime */
		/** Prepare communication variables */
		sp_context.rx_communication.lasting = *p_size;
		sp_context.rx_communication.received = 0;
		sp_context.rx_communication.p_data = p_data;
	    /** Lets enable the UART interrupt */
		/** Remove previous threshold value for reception */
		sp_context.port.uart.reg_uart->rx_ctrl &= ~C_UART_RXCTRL_RXCNT_MASK;
		/** Recompute threshold */
		if( C_UART_DATA_MAX_THRESHOLD_RX > sp_context.rx_communication.lasting )
		{
			sp_context.rx_communication.threshold = sp_context.rx_communication.lasting;
		}
		else
		{
			sp_context.rx_communication.threshold = C_UART_DATA_MAX_THRESHOLD_RX;
		}
		sp_context.port.uart.reg_uart->rx_ctrl = ( ( ( sp_context.rx_communication.threshold - 1 ) << C_UART_RXCTRL_RXCNT_OFST ) & C_UART_RXCTRL_RXCNT_MASK );
		/** Enable RX */
		M_UART_RX_ENABLE(sp_context.port.uart.reg_uart);
		/** Enable interrupt */
		metal_uart_receive_interrupt_enable(sp_context.port.uart.uart0);
	    /** Wait until reception is over */
	    while( sp_context.rx_communication.lasting > 0 )
	    {
	    	/** Waiting loop */
#ifdef _WITH_QEMU_
	    	/** QEMU specific */
	    	if( sp_context.port.uart.reg_uart->ie & sp_context.port.uart.reg_uart->ip )
	    	{
	    		/** IRQ treatment */
	    		sp_uart_rx_isr(0, (void*)p_ctx);
	    	}
#endif /* _WITH_QEMU_ */
	    }
	    /** No error */
	    err = NO_ERROR;
	}
sp_uart_receive_buffer_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_uart_send_buffer(t_context *p_ctx, uint8_t *p_data, uint32_t size)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint32_t									lasting = 0;

	/** Check input pointer */
	if( !p_ctx || !p_data )
	{
		/** Pointers should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !size )
	{
		/** Size should not be null */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Disable RX */
		M_UART_RX_DISABLE(sp_context.port.uart.reg_uart);
		/** Disable interrupt */
		sp_context.port.uart.reg_uart->ie &= ~( C_UART_IE_TXWM_MASK | C_UART_IE_RXWM_MASK );
		/** First register handler for TX interruption */
		sp_context.tx_communication.lasting = size;
		sp_context.tx_communication.sent = FALSE;
		sp_context.tx_communication.transmitted = 0;
		/** Update contextual pointer data */
		sp_context.tx_communication.p_data = p_data;
	    /** Set TX watermark for sending procedure */
		/** Remove previous threshold value for reception */
		sp_context.port.uart.reg_uart->tx_ctrl &= ~C_UART_TXCTRL_TXCNT_MASK;
		/** Recompute threshold */
		sp_context.port.uart.reg_uart->tx_ctrl = ( ( 1 << C_UART_TXCTRL_TXCNT_OFST ) & C_UART_TXCTRL_TXCNT_MASK );
		/** Enable TX */
		M_UART_TX_ENABLE(sp_context.port.uart.reg_uart);
		/** Enable interrupt */
		M_UART_UNMASK_TX_IRQ(sp_context.port.uart.reg_uart);
	    /** Wait until reception is over */
	    while( FALSE == sp_context.tx_communication.sent )
	    {
	    	/** Waiting loop */
#ifdef _WITH_QEMU_
	    	/** QEMU specific */
	    	if( sp_context.port.uart.reg_uart->ie & sp_context.port.uart.reg_uart->ip )
	    	{
	    		/** IRQ treatment */
	    		sp_uart_tx_isr(0, (void*)p_ctx);
	    	}
#endif /* _WITH_QEMU_ */
	    }
		/** Check if everything has been sent */
		if( sp_context.tx_communication.transmitted != size )
		{
			/** Not all of the characters have been sent */
			err = N_SP_ERR_SUP_TX_COMMUNICATION_FAILURE;
		}
		else
		{
			/** All characters have been sent */
			err = NO_ERROR;
		}
	}
sp_uart_send_buffer_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_check_stimulus(t_context *p_ctx)
{
	uint32_t									sup_disable = 0;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Retrieve information from SUP_REQ and SUP_DISABLE */
		/** Check if SUP has been disabled */
		err = sbrm_read_otp(p_ctx, C_OTP_SUP_DISABLE_OFST, (uint8_t*)&sup_disable, C_OTP_SUP_DISABLB_SIZE);
		if( err )
		{
			/** Can't read OTP, critical problem */
			err = GENERIC_ERR_CRITICAL;
		}
		else if( C_OTP_SUP_DISABLE_PATTERN == ( C_OTP_SUP_DISABLE_PATTERN_MASK & sup_disable ) )
		{
			/** SUP must not be opened */
			sp_context.state = N_SP_STATE_DISABLE;
			err = N_SP_ERR_SUP_NO_SESSION_ALLOWED;
		}
		else
		{
			/** SUP can be opened */
#ifdef _FPGA_SPECIFIC_
			/** Set state for SUP */
			sp_context.state = N_SP_STATE_NOT_INITIALIZED;
			/** Read MSEL value @ 0x1000 */
			if( *((uint32_t*)0x1000) )
			{
				/** SUP session is to be opened */
				sp_context.port.bus_id = N_SBRM_BUSID_UART;
				err = NO_ERROR;
			}
			else
			{
				/** SUP session is NOT to be opened */
				sp_context.port.bus_id = N_SBRM_BUSID_NOBUS;
				/** No error, just no SUP session
				 * Inform the caller */
				err = N_SP_ERR_SUP_NO_SESSION_ALLOWED;
			}
/**  */
#else
			/** So check if SUP_REQ is set to definitely open SUP session */
			/** Base address of SCR block (0x4_F001_0000) + offset 0x0, bit 4 */
			if( C_SP_SUP_REQ_PATTERN != ( METAL_REG(0x4f0010000,0) & C_SP_SUP_REQ_MASK ) )
			{
				/** Set state for SUP */
				sp_context.state = N_SP_STATE_NOT_INITIALIZED;
				/** SUP session is NOT to be opened */
				sp_context.port.bus_id = N_SBRM_BUSID_NOBUS;
				/** No error, just no SUP session
				 * Inform the caller */
				err = N_SP_ERR_SUP_NO_SESSION_ALLOWED;
			}
			else
			{
				/** Set state for SUP */
				sp_context.state = N_SP_STATE_NOT_INITIALIZED;
				/** SUP session is to be opened */
				sp_context.port.bus_id = N_SBRM_BUSID_UART;
				err = NO_ERROR;
			}
#endif /* _FPGA_SPECIFIC_ */
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_get_port_conf(t_context *p_ctx)
{
	int8_t										slot;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Read from OTP UART configuration if any */
		for( slot = C_OTP_UART_SLOT_MAX;slot >= 0;slot-- )
		{
			/** Read configuration from OTP */
			err = sbrm_read_otp(p_ctx, ( C_OTP_UART_AREA_OFST + ( slot * C_OTP_UART_ELMNT_SIZE ) ), (uint8_t*)&sp_context.port.config, C_OTP_UART_ELMNT_SIZE);
			if( err )
			{
				/** Can't read OTP ... shouldn't happened */
				err = GENERIC_ERR_CRITICAL;
			}
			/** Check if baudrate value has been found */
			else if( C_PATTERN_VIRGIN_32BITS != sp_context.port.config[C_SP_SUP_PORT_CONF_BAUDRATE_OFST] )
			{
				/** No error */
				err = NO_ERROR;
				break;
			}
			else
			{
				/** No configuration */
				err = N_SP_ERR_SUP_BAD_PARAMS;
			}
		}
		/**  */
		if ( N_SP_ERR_SUP_BAD_PARAMS == err )
		{
			/** Set default values for parameters */
			sp_context.port.config[C_SP_SUP_PORT_CONF_BAUDRATE_OFST] = C_SP_SUP_PORT_CONF_PARAMS0;
			sp_context.port.config[C_SP_SUP_PORT_CONF_PARAMS_OFST] = C_SP_SUP_PORT_CONF_PARAMS1;
			/** No error then */
			err = NO_ERROR;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_check_pkchain(t_context *p_ctx, uint8_t *p_pkchain, uint32_t nb_certs, t_km_key *p_key_cert)
{
	uint32_t									j;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint8_t										*p_tmp;
	/** PK Chain key to be checked */
	t_km_key									key_tmp;

	/** Check input pointers */
	if( !p_ctx || !p_pkchain || !p_key_cert )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !nb_certs )
	{
		/** It should have, at least, one certificates */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Assign work pointer */
		p_tmp = p_pkchain;
		/** Check PK chain within signature */
		for( j = 0;j < nb_certs;j++ )
		{
			/** Point on next key element */
			key_tmp.ecdsa.p_x = (uint8_t*)p_tmp;
			key_tmp.ecdsa.p_y = (uint8_t*)( key_tmp.ecdsa.p_x + C_EDCSA384_SIZE );
			key_tmp.certificate.p_x = (uint8_t*)( key_tmp.ecdsa.p_y + C_EDCSA384_SIZE );
			key_tmp.certificate.p_y = (uint8_t*)( key_tmp.certificate.p_x + C_EDCSA384_SIZE );
			/** Then verify certificate */
			err = km_verify_signature(p_ctx,
										(uint8_t*)key_tmp.ecdsa.p_x,
										(uint32_t)( 2 * C_EDCSA384_SIZE ),
										(uint8_t*)key_tmp.certificate.p_x,
										N_KM_ALGO_ECDSA384,
										*p_key_cert);
			if( err )
			{
				/** Error in cryptographic computation */
				goto sp_sup_check_pkchain_out;
			}
			/** If signature checked is ok, then checked key becomes new reference key */
			p_key_cert->ecdsa.p_x = key_tmp.ecdsa.p_x;
			p_key_cert->ecdsa.p_y = key_tmp.ecdsa.p_y;
			p_key_cert->certificate.p_x = key_tmp.certificate.p_x;
			p_key_cert->certificate.p_y = key_tmp.certificate.p_y;
			/** Update pointer to point on next PKChain element*/
			p_tmp += ( 4 * C_EDCSA384_SIZE );
		}
		/** Now last checked key is the one to use for packet verification,
		/** No error */
		err = NO_ERROR;
	}
sp_sup_check_pkchain_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_check_security(t_context *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									j;
	uint_pltfrm									offset = 0;
	uint32_t									key_cert_size = 0;
	uint8_t										*p_end_certificate;
	size_t										hash_len = 0;
	t_sig_element								*p_signature_element;
	t_km_context								*p_km_ctx;
	e_km_keyid									key_id;
	t_km_key									key_cert;
	ecc_affine_point_t			Q;
	ecdsa_signature_t					signature;


	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !p_ctx->p_scl_hash_ctx )
	{
		/**  */
		err = N_SP_ERR_NOT_INITIALIZED;
	}
	else if( !p_ctx->p_km_context )
	{
		/** KM context pointer should not be null */
		err = GENERIC_ERR_CRITICAL;
	}
	else if( !p_ctx->p_scl_hash_ctx )
	{
		/** SCL hash structure must not be null */
		err = GENERIC_ERR_INVAL;
	}
	/** Retrieve information from work buffer */
	else if( !sp_context.security.sig_buf )
	{
		/** Should not happen */
		err = GENERIC_ERR_CRITICAL;
	}
	else
	{
		/** KM context is set */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		/** Point on signature element */
		p_signature_element = (t_sig_element*)sp_context.security.sig_buf;
		/** Check the signature(s) ********************************************/
		for( i = 0;i < sp_context.security.nb_signatures;i++ )
		{
			/** Initialize buffer */
			memset((void*)&p_km_ctx->valid_sk, 0x00, sizeof(t_key_data));
			/** Assign pointers */
			key_cert.p_descriptor = (uint32_t*)&p_km_ctx->valid_sk.algo;
			key_cert.ecdsa.p_x = (uint8_t*)p_km_ctx->valid_sk.key;
			key_cert.ecdsa.p_y = (uint8_t*)( p_km_ctx->valid_sk.key + C_EDCSA384_SIZE );
			key_cert.certificate.p_x = (uint8_t*)p_km_ctx->valid_sk.certificate;
			key_cert.certificate.p_y = (uint8_t*)( p_km_ctx->valid_sk.certificate + C_EDCSA384_SIZE );
			/** Retrieve key of session */
			err = km_get_key(p_ctx,
								sp_context.sup.key_id,
								(t_km_key*)&key_cert,
								(uint32_t*)&key_cert_size);
			if( err )
			{
				/** Should not happen */
				err = GENERIC_ERR_CRITICAL;
				goto sp_sup_check_security_out;
			}
			/** Check key then ... */
			switch( sp_context.sup.key_id )
			{
				case N_KM_KEYID_STK:
				case N_KM_KEYID_SSK:
					/** No verification needed */
					break;
				case N_KM_KEYID_PSK:
				{
					uint32_t									key_size_ref;
					t_km_key									key_ref;
					t_key_data									key_data_ref;

					/** Assign pointers */
					key_ref.p_descriptor = (uint32_t*)&p_km_ctx->valid_sk.algo;
					key_ref.ecdsa.p_x = (uint8_t*)p_km_ctx->valid_sk.key;
					key_ref.ecdsa.p_y = (uint8_t*)( p_km_ctx->valid_sk.key + C_EDCSA384_SIZE );
					key_ref.certificate.p_x = (uint8_t*)p_km_ctx->valid_sk.certificate;
					key_ref.certificate.p_y = (uint8_t*)( p_km_ctx->valid_sk.certificate + C_EDCSA384_SIZE );
					/** Retrieve PSK's reference key */
					err = km_get_key(p_ctx,
										N_KM_KEYID_SSK,
										(t_km_key*)&key_ref,
										(uint32_t*)&key_size_ref);
					if( err )
					{
						/** Should not happen */
						err = GENERIC_ERR_CRITICAL;
						goto sp_sup_check_security_out;
					}

					/** Verify signature */
					err = km_verify_signature(p_ctx,
												(uint8_t*)&p_km_ctx->valid_sk,
												( sizeof(p_km_ctx->valid_sk) - sizeof(p_km_ctx->valid_sk.certificate) ),
												(uint8_t*)key_cert.certificate.p_x,
												(e_km_support_algos)p_km_ctx->valid_sk.algo,
												key_ref);
					if( err )
					{
						/** Key's certificate not valid */
						err = N_SP_ERR_SUP_KEY_VERIF_FAILED;
						goto sp_sup_check_security_out;
					}
					break;
				}
				case N_KM_KEYID_CUK:
				case N_KM_KEYID_CSK:
					/** Verify hash */
					err = km_verify_hash(p_ctx,
											(uint8_t*)&p_km_ctx->valid_sk,
											( sizeof(p_km_ctx->valid_sk) - sizeof(p_km_ctx->valid_sk.certificate) ),
											(uint8_t*)key_cert.certificate.p_x);
					if( err )
					{
						/** Key's certificate not valid */
						err = N_SP_ERR_SUP_KEY_VERIF_FAILED;
						goto sp_sup_check_security_out;
					}
					break;
				default:
					/** Should not happen */
					err = GENERIC_ERR_CRITICAL;
					goto sp_sup_check_security_out;
			}

			/** Check if signature matches expected one */
			if( i != p_signature_element->sig_nb )
			{
				/**  */
				err = N_SP_ERR_SUP_SIG_NB_DONT_MATCH;
				goto sp_sup_check_security_out;
			}
			/** Check algorithm */
			else if( N_KM_ALGO_ECDSA384 != p_signature_element->algo )
			{
				/** Algorithm is ont the one expected */
				err = N_SP_ERR_SUP_ALGO_MISMATCH;
				goto sp_sup_check_security_out;
			}
			else if( sp_context.sup.key_id != p_signature_element->skid )
			{
				/** Signing key is not the one expected */
				err = N_SP_ERR_SUP_KEY_MISMATCH;
				goto sp_sup_check_security_out;
			}
			/** PKChain is present - Update certificate key to use for 'end certificate' */
			if( p_signature_element->nb_certificates )
			{
				/** Call specific function for PK chain processing */
				err = sp_sup_check_pkchain(p_ctx,
											(uint8_t*)( (uint_pltfrm)p_signature_element + (uint_pltfrm)sizeof(t_sig_element) ),
											p_signature_element->nb_certificates,
											(t_km_key*)&key_cert);
				if( err )
				{
					/** At least one certificate check failed */
					goto sp_sup_check_security_out;
				}
			}
			/** Now check 'end' certificate */
			/** Process hash digest on message */
			/** Initialization */
#ifdef _WITH_GPIO_CHARAC_
			/** Blue LED Off/On */
			metal_led_off(p_ctx->led[2]);
			metal_led_on(p_ctx->led[2]);
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err = scl_sha_init((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
								SCL_HASH_SHA384);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
			if( SCL_OK != err )
			{
				/** Critical error */
				err = N_SP_ERR_SUP_CRYPTO_FAILURE;
				goto sp_sup_check_security_out;
			}
			/** Header */
			if( sp_context.sup.rx_hdr.command_length )
			{
				/** 'address' field must be counted */
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
				err = scl_sha_core((metal_scl_t*)p_ctx->p_metal_sifive_scl,
									(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
									(const uint8_t*)&sp_context.sup.rx_hdr,
									sizeof(t_sp_sup_rx_pckt_hdr));
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
			}
			else
			{
				/** 'address' field must not be counted, because there's no 'address' field */
#ifdef _WITH_GPIO_CHARAC_
				/** Set GPIO SHA high */
				metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
				err = scl_sha_core((metal_scl_t*)p_ctx->p_metal_sifive_scl,
									(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
									(const uint8_t*)&sp_context.sup.rx_hdr,
									( sizeof(t_sp_sup_rx_pckt_hdr) - sizeof(sp_context.sup.rx_hdr.address) ));
#ifdef _WITH_GPIO_CHARAC_
				/** Set GPIO SHA low */
				metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
			}
			if( SCL_OK != err )
			{
				/** Critical error */
				err = N_SP_ERR_SUP_CRYPTO_FAILURE;
				goto sp_sup_check_security_out;
			}
			/** Real payload, data after 'address' field, is pointed in sp_context.sup.payload.p_data */
			/** Payload if any */
			if( sp_context.sup.rx_hdr.command_length )
			{
				/** Let's process the real payload - without 'address' field then */
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
				err = scl_sha_core((metal_scl_t*)p_ctx->p_metal_sifive_scl,
									(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
									(const uint8_t*)sp_context.sup.payload.p_data,
									sp_context.sup.payload.size);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
				if( SCL_OK != err )
				{
					/** Critical error */
					err = N_SP_ERR_SUP_CRYPTO_FAILURE;
					goto sp_sup_check_security_out;
				}
			}
			/** Process security elements now - rawly , remove signature size, certificate numbers, signature number and skid */
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err = scl_sha_core((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
								(const uint8_t*)sp_context.security.uid,
								/** Size to check starts from beginning of "Security Format" until "certs number" field not included */
								( sizeof(sp_context.security.uid) + sizeof(sp_context.security.nb_signatures) ));
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
			if( SCL_OK != err )
			{
				/** Critical error */
				err = N_SP_ERR_SUP_CRYPTO_FAILURE;
				goto sp_sup_check_security_out;
			}
			/** Process moving part if multiple signatures */
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err = scl_sha_core((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
								(const uint8_t*)p_signature_element,
								/** Size to check starts from beginning of "Security Format" until "certs number" field not included */
								( sizeof(p_signature_element->sig_nb) + sizeof(p_signature_element->skid) + sizeof(p_signature_element->algo) ));
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
			if( SCL_OK != err )
			{
				/** Critical error */
				err = N_SP_ERR_SUP_CRYPTO_FAILURE;
				goto sp_sup_check_security_out;
			}

			/** Then finish computation */
			hash_len = sizeof(p_ctx->digest);
			memset((void*)p_ctx->digest, 0x00, C_SP_SUP_HASH_SIZE_IN_BYTES);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err = scl_sha_finish((metal_scl_t*)p_ctx->p_metal_sifive_scl,
									(scl_sha_ctx_t*)p_ctx->p_scl_hash_ctx,
									p_ctx->digest,
									&hash_len);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
#endif /* _WITH_GPIO_CHARAC_ */
			if( SCL_OK != err )
			{
				/** Critical error */
				err = N_SP_ERR_SUP_CRYPTO_FAILURE;
				goto sp_sup_check_security_out;
			}
			/** Now verify signature */
			p_end_certificate = (uint8_t*)( (uint_pltfrm)p_signature_element +
											(uint_pltfrm)sizeof(t_sig_element) );
			/** If there is at least one certificate */
			if( p_signature_element->nb_certificates )
			{
				p_end_certificate += (uint_pltfrm)( p_signature_element->nb_certificates * ( 4 * C_EDCSA384_SIZE ) );
			}
			/** Set parameters */
			Q.x = key_cert.ecdsa.p_x;
			Q.y = key_cert.ecdsa.p_y;
			signature.r = p_end_certificate;
			signature.s = p_end_certificate + C_EDCSA384_SIZE;
			/** Call SCL ECDSA verification function */
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO check ECDSA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA_ECDSA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
			err = scl_ecdsa_verification((metal_scl_t*)p_ctx->p_metal_sifive_scl,
											&ecc_secp384r1,
											(const ecc_affine_const_point_t *const)&Q,
											(const ecdsa_signature_const_t *const)&signature,
											p_ctx->digest,
											C_SP_SUP_HASH_SIZE_IN_BYTES);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO check ECDSA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA_ECDSA, 0);
			/** Blue LED Off */
			metal_led_off(p_ctx->led[2]);
#endif /* _WITH_GPIO_CHARAC_ */
			if( SCL_OK != err )
			{
				/** Cryptographic computation failed */
				err = N_SP_ERR_SUP_PACKET_REJECTED;
				goto sp_sup_check_security_out;
			}
			else
			{
				/** Point on next signature element if any */
				p_signature_element = (t_sig_element*)( (uint_pltfrm)p_end_certificate +
														(uint_pltfrm)( 2 * C_EDCSA384_SIZE ) );
				/** No error */
				err = NO_ERROR;
			}
		}
		/** If we're here, it means that signature(s) is(are) checked Ok */
	}
sp_sup_check_security_out:
	/** End Of Function */
	return err;
}
/******************************************************************************/
int_pltfrm sp_sup_process_cmd(t_context *p_ctx, uint8_t **p_data, uint32_t *p_length)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointer */
	if( !p_ctx || !p_length )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Check received command */
		switch( sp_context.sup.rx_hdr.command_type )
		{
			case N_SP_SUP_SEGMENT_TYPE_COPY:
				/** Copy data to destination address */
//				err = sp_treat_copy();
				/** Already done when receiving command header - :/ */
				err = NO_ERROR;
				/** No specific data to return */
				*p_length = 0;
				break;
			case N_SP_SUP_SEGMENT_TYPE_WRITECSK:
				err = sp_treat_writekey(p_ctx,
										N_KM_KEYID_CSK,
										sp_context.sup.payload.p_data,
										( sp_context.sup.rx_hdr.command_length - sizeof(uint32_t)));
				if( NO_ERROR == err )
				{
					/** No specific data to return */
					*p_length = 0;
				}
				break;
			case N_SP_SUP_SEGMENT_TYPE_WRITECUK:
				err = sp_treat_writekey(p_ctx,
										N_KM_KEYID_CUK,
										sp_context.sup.payload.p_data,
										( sp_context.sup.rx_hdr.command_length - sizeof(uint32_t)));
				if( NO_ERROR == err )
				{
					/** No specific data to return */
					*p_length = 0;
				}
				break;
			case N_SP_SUP_SEGMENT_TYPE_WRITEPMUSK:
				err = sp_treat_writekey(p_ctx,
										N_KM_KEYID_PSK,
										sp_context.sup.payload.p_data,
										( sp_context.sup.rx_hdr.command_length - sizeof(uint32_t)));
				if( NO_ERROR == err )
				{
					/** No specific data to return */
					*p_length = 0;
				}
				break;
			case N_SP_SUP_SEGMENT_TYPE_GETINFO:
				err = sp_treat_getinfo(p_ctx, (uint8_t**)p_data, p_length);
				break;
			case N_SP_SUP_SEGMENT_TYPE_EXECUTE:
				err = sp_treat_execute(p_ctx,
										*((uint32_t*)work_buf),
										sp_context.sup.payload.p_data,
										( sp_context.sup.rx_hdr.command_length - sizeof(uint32_t)),
										(uint8_t**)p_data,
										p_length);
				break;
			default:
				err = N_SP_ERR_SUP_CMD_NOT_SUPPORTED;
				break;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_send_response(t_context *p_ctx, uint8_t *p_data, uint32_t length)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointers */
	if( !p_ctx || !p_data )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( !length )
	{
		/** Nothing to send - should not happen */
		err = GENERIC_ERR_INVAL;
	}
	else
	{
		/** Send  */
		err = sp_uart_send_buffer(p_ctx, p_data, length);
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_initialize_communication(t_context *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input parameter */
	if( !p_ctx )
	{
		/** Pointer must not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_initialize_communication_out;
	}
	/** Retrieve configuration parameters for this port */
	err = sp_sup_get_port_conf(p_ctx);
	if ( err )
	{
		/** Should not happen */
		err = GENERIC_ERR_CRITICAL;
		goto sp_sup_initialize_communication_out;
	}
	/** Initialize port */
	switch( sp_context.port.bus_id )
	{
		case N_SBRM_BUSID_UART:
			metal_uart_init(sp_context.port.uart.uart0, sp_context.port.config[C_SP_SUP_PORT_CONF_BAUDRATE_OFST]);
			err = NO_ERROR;
			break;
		default:
			err = N_SP_ERR_SUP_COM_PORT_NOT_HANDLED;
			goto sp_sup_initialize_communication_out;
	}
sp_sup_initialize_communication_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_prep_com(void)
{
	/** Current security key used */
	e_km_keyid									key_id = sp_context.sup.key_id;
	/** SUP mode if any */
	e_sp_sup_mode								mode = sp_context.sup.mode;

	/** Zero-ize SUP context */
	memset((void*)&sp_context.sup, 0x00, sizeof(t_sp_sup_context));
	/** Restore essential parameters */
	sp_context.sup.key_id = key_id;
	sp_context.sup.mode = mode;
	/** Fill out several fields */
	/** Initialize contextual variables */
	sp_context.sup.first_pkt = TRUE;
	sp_context.sup.current_session_id = 0;
	sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SYNC;
	sp_context.state = N_SP_STATE_IDLE;
	/** End Of Function */
	return NO_ERROR;
}

/******************************************************************************/
int_pltfrm sp_sup_open_communication(t_context *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	int_pltfrm 									err_cmd = GENERIC_ERR_UNKNOWN;
	uint32_t									length = 0;
	uint8_t										*p_data;

	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_open_communication_out;
	}
	/** Prepare communication context */
	err = sp_sup_prep_com();
	if( err )
	{
		/** Communication context preparation failed, therefore exit with error */
		goto sp_sup_open_communication_out;
	}
	/** Loop to receive packets - endless loop until communication is closed */
	while( ( NO_ERROR == err ) && ( C_SP_LAST_PACKET_NB != sp_context.sup.rx_hdr.last_packet ) )

	{
		/** Receive and process header */
		err = sp_sup_receive_packet(p_ctx);
		if( err )
		{
			/** Packet cannot be retrieved for any reason, exit with error */
			goto sp_sup_open_communication_out;
		}
		/** Check signature */
		err = sp_sup_check_security((t_context*)p_ctx);
		if ( err )
		{
			/** Exit and try to launch application if any */
			/** Because of security problem, no answer is sent back to Host */
			goto sp_sup_open_communication_out;
		}
		/** Process command then */
		err_cmd = sp_sup_process_cmd((t_context*)p_ctx, (uint8_t**)&p_data, (uint32_t*)&length);
		if( N_SP_ERR_RESET_PLATFORM == err_cmd )
		{
			/** Fill parameter to send error code to Host */
			/** Send packet response */
			err = sp_sup_packet_response(p_ctx,
											NO_ERROR,
											sp_context.sup.current_session_id,
											sp_context.sup.current_packet_nb,
											(uint8_t*)p_data,
											length);
			/** Must stop the loop to reset platform */
			err = err_cmd;
		}
		else
		{
			/** Send packet response */
			err = sp_sup_packet_response(p_ctx,
											err_cmd,
											sp_context.sup.current_session_id,
											sp_context.sup.current_packet_nb,
											(uint8_t*)p_data,
											length);
		}
		/** Reinitialize parameters */
		memset((void*)&sp_context.rx_communication, 0x00, sizeof(sp_context.rx_communication));
		memset((void*)&sp_context.tx_communication, 0x00, sizeof(sp_context.tx_communication));
	}
sp_sup_open_communication_out:
	/** End Of Function */
	return err;
}


/******************************************************************************/
void sp_sup_close_communication(t_context *p_ctx)
{
	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer should not be null */
	}
	else
	{
		/** Close bus */
		/** Disable interruptions */
		M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
		M_UART_MASK_TX_IRQ(sp_context.port.uart.reg_uart);
		/** Disable RX and TX */
		M_UART_RX_DISABLE(sp_context.port.uart.reg_uart);
		M_UART_TX_DISABLE(sp_context.port.uart.reg_uart);
	}
	/** End Of Function */
	return;
}

/******************************************************************************/
int_pltfrm sp_treat_writekey(t_context *p_ctx, e_km_keyid key_id, uint8_t *p_data, uint32_t length)
{
	uint32_t									slot = 0;
	uint32_t									key_size_ref = 0;
	uint32_t									size;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint_pltfrm									offset = 0;
	size_t										hash_len = 0;
	e_km_keyid									key_id_ref;
	t_key_data									key_data_ref;
	t_key_data									*p_key_data;
	t_km_key									key;
	t_km_key									key_ref;


	/** Check input parameters */
	if( ( !p_ctx ) || ( !p_data ) )
	{
		/** NULL pointer thus error */
		err = GENERIC_ERR_NULL_PTR;
	}
	else if( sizeof(t_key_data) != length )
	{
		/** length must be */
		err = N_SP_ERR_SUP_CANT_PROCEEED;
	}
	else
	{
		/** Fill local structure */
		p_key_data = (t_key_data*)p_data;
		/** Check algorithm */
		if( N_KM_ALGO_ECDSA384 != p_key_data->algo )
		{
			/** Not the good one */
			err = N_SP_ERR_SUP_ALGO_MISMATCH;
			goto sp_treat_writekey_out;
		}
		/** ECDSA384 size is 48 Bytes * 8bits = 0x30 * 8 */
		else if( (uint16_t)( C_EDCSA384_SIZE * 8 ) != p_key_data->key_size_bits )
		{
			/**  */
			err = N_SP_ERR_SUP_WRITEKEY_FAILED;
			goto sp_treat_writekey_out;
		}
		/** Retrieve KM context structure */
		if( !p_ctx->p_km_context )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_treat_writekey_out;
		}
		/** Check if there's a free slot depending on key identifier */
		switch( key_id )
		{
			case N_KM_KEYID_CSK:
				/** Set parameters to enter the loop */
				err = NO_ERROR;
				slot = C_OTP_NB_CSK_SLOTS;
				/** Find last free slot */
				while( ( slot > 0 ) && ( NO_ERROR == err ) )
				{
					/**  */
					err = km_check_key_slot(p_ctx, --slot, N_KM_KEYID_CSK);
				}
				/** Check loop stop condition */
				if( ( C_OTP_CSK_SLOT_MAX == slot ) && ( N_KM_ERR_NOT_VIRGIN == err ) )
				{
					/** No free slot then can't program key */
					goto sp_treat_writekey_out;
				}
				else if( NO_ERROR == err )
				{
					/** Then slot 0 is free to use because has been stopped with 'i = 0' condition */
				}
				else if( N_KM_ERR_NOT_VIRGIN == err )
				{
					/** One slot free slot has been found one upper of the current one */
					slot++;
				}
				else
				{
					/** Slot is not free to use */
					goto sp_treat_writekey_out;
				}
				/** Is given reference key is the expected one ? */
				if( N_KM_KEYID_CUK != p_key_data->sign_key_id )
				{
					/** It does not match */
					err = N_SP_ERR_SUP_KEY_MISMATCH;
					goto sp_treat_writekey_out;
				}
				/** Set offset and length */
				offset = C_OTP_CSK_AREA_OFST + ( slot * C_OTP_CSK_AERA_SIZE );
				size = C_OTP_CSK_AERA_SIZE;
				break;
			default:
				/** Programming of this key is not supported */
				err = N_SP_ERR_SUP_KEY_NOT_SUPPORTED;
				goto sp_treat_writekey_out;
		}
		/** Everything is fine from destination point of view, let's check Key signature */
		/** Retrieve reference key */
		key_ref.p_descriptor = (uint32_t*)&key_data_ref.algo;
		key_ref.ecdsa.p_x = (uint8_t*)key_data_ref.key;
		key_ref.ecdsa.p_y = (uint8_t*)( key_ref.ecdsa.p_x + C_EDCSA384_SIZE );
		key_ref.certificate.p_x = (uint8_t*)key_data_ref.certificate;
		key_ref.certificate.p_y = (uint8_t*)( key_ref.certificate.p_x + C_EDCSA384_SIZE );
		err = km_get_key(p_ctx,
							(e_km_keyid)p_key_data->sign_key_id,
							(t_km_key*)&key_ref,
							(uint32_t*)&key_size_ref);
		if( err )
		{
			/** Should not happen */
			goto sp_treat_writekey_out;
		}
		/** Then verify key's certificate */
		err = km_verify_signature(p_ctx,
									(uint8_t*)p_key_data,
									(uint32_t)( sizeof(t_key_data) - sizeof(p_key_data->certificate) ),
									p_key_data->certificate,
									p_key_data->algo,
									key_ref);
		if( err )
		{
			/** Can't proceed to CSK programming  */
			err = N_SP_ERR_SUP_WRITEKEY_FAILED;
			goto sp_treat_writekey_out;
		}
		/** Now compute hash for either CUK, either CSK */
		switch( key_id )
		{
			case N_KM_KEYID_CSK:
				/** Compute hash, and put it in 'certificate' location */
				hash_len = sizeof(p_key_data->certificate);
#ifdef _WITH_GPIO_CHARAC_
			/** Blue LED Off/On */
			metal_led_off(p_ctx->led[2]);
			metal_led_on(p_ctx->led[2]);
			/** Set GPIO SHA high */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 1);
#endif /* _WITH_GPIO_CHARAC_ */
				err = scl_sha((metal_scl_t*)p_ctx->p_metal_sifive_scl,
								SCL_HASH_SHA384,
								(const uint8_t *const)p_key_data,
								(size_t)( sizeof(t_key_data) - sizeof(p_key_data->certificate) ),
								(uint8_t *const)p_key_data->certificate,
								&hash_len);
#ifdef _WITH_GPIO_CHARAC_
			/** Set GPIO SHA low */
			metal_gpio_set_pin(p_ctx->gpio0, C_GPIO0_SHA, 0);
			/** Blue LED Off */
			metal_led_off(p_ctx->led[2]);
#endif /* _WITH_GPIO_CHARAC_ */
				if( SCL_OK != err )
				{
					/** Critical error */
					err = GENERIC_ERR_CRITICAL;
					goto sp_treat_writekey_out;
				}
				break;
			case N_KM_KEYID_PSK:
				/** Nothing to do keep given certificate */
			default:
				/** Programming of this key is not supported */
				err = N_SP_ERR_SUP_KEY_NOT_SUPPORTED;
				goto sp_treat_writekey_out;
		}
		/** Now program CSK in storage area */
		err = sbrm_write_otp(p_ctx, offset, (const uint8_t*)p_key_data, size);
	}
sp_treat_writekey_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_treat_execute(t_context *p_ctx, uint_pltfrm jump_addr, uint8_t *p_arg, uint32_t length, uint8_t **p_data, uint32_t *p_length)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint_pltfrm (*applet_fct_ptr)(uint8_t* p_arg, uint32_t length, uint8_t **p_ret_data, uint32_t *p_ret_size);

	/** Check input pointer */
	if( !p_arg )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		uint32_t								arg0 = (uint32_t)p_arg;
		uint32_t								arg1 = length;

		/** Check jump address */
		if( (  (uint_pltfrm)p_ctx->free_ram_end < jump_addr ) ||
			( (uint_pltfrm)p_ctx->free_ram_start > jump_addr ) )
		{
			/**  */
			err = N_SP_ERR_SUP_JUMP_ADDR_FAILURE;
			goto sp_treat_execute_out;
		}
		/** Assign function pointer */
		applet_fct_ptr = (uint_pltfrm*)jump_addr;
		/** Call function */
		err = applet_fct_ptr(p_arg, length, p_data, p_length);

	}
sp_treat_execute_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_treat_getinfo(t_context *p_ctx, uint8_t** p_data, uint32_t *p_length)
{
	uint32_t									tmp = 0;
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	t_getinfo_template							*p_tmp = (t_getinfo_template*)work_buf;
	t_km_context								*p_km_ctx;
	t_ppm_context								*p_ppm_ctx;

	/** Check input pointer */
	if( !p_ctx || !p_data || !p_length )
	{
		/** Pointer should not be null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Assign pointer */
		p_km_ctx = (t_km_context*)p_ctx->p_km_context;
		p_ppm_ctx = (t_ppm_context*)p_ctx->p_ppm_context;
		/** Erase buffer */
		memset((void*)work_buf, 0x00, sizeof(t_getinfo_template));
		/** Assign output pointer */
		*p_data = (uint8_t*)p_tmp;
		/** Retrieve UID */
		err = sbrm_get_uid(p_ctx, p_tmp->uid);
		if( err )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_treat_getinfo_out;
		}
		/** Retrieve SBC version */
		err = sbrm_get_sbr_version((uint32_t*)&p_tmp->sbr_version);
		if( err )
		{
			/** Should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_treat_getinfo_out;
		}
		/** Retrieve Life Cycle Phase */
		p_tmp->lcp = p_ppm_ctx->lifecycle_phase;
		/** Retrieve JTA information */
		p_tmp->jtag = 0;
		/** Retrieve RMA Mode from OP/eFuse */
		err = sbrm_read_otp(p_ctx, C_OTP_RMA_CSK_OFST, (uint8_t*)&tmp, C_OTP_RMA_CSK_SIZE);
		if( NO_ERROR == err )
		{
			p_tmp->rma_mode = ( tmp >> C_OTP_RMA_CSK_PATTERN_OFST ) & C_OTP_RMA_CSK_PATTERN_MASK_NOOFST;
		}
		else
		{
			p_tmp->rma_mode = 0x000000ef;
		}
		err = sbrm_read_otp(p_ctx, C_OTP_RMA_PMU_OFST, (uint8_t*)&tmp, C_OTP_RMA_PMU_SIZE);
		if( NO_ERROR == err )
		{
			p_tmp->rma_mode |= ( ( ( tmp >> C_OTP_RMA_PMU_PATTERN_OFST ) & C_OTP_RMA_PMU_PATTERN_MASK_NOOFST ) << 8 );
		}
		else
		{
			p_tmp->rma_mode |= 0x0000be00;
		}
		/** Retrieve Applet memory area */
		p_tmp->applet_start = (uint_pltfrm)&__sbrm_free_start_addr;
		p_tmp->applet_end = (uint_pltfrm)&__sbrm_free_end_addr;
		/** Retrieve CSK free slot index */
		p_tmp->csk_slot = p_km_ctx->index_free_csk;
		/** Set size of returned data */
		*p_length = sizeof(t_getinfo_template);
		err = NO_ERROR;
	}
sp_treat_getinfo_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_pkt_fields(uint8_t **p_data, uint32_t *p_size)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointers - don't care about '*p_data' to be null */
	if( !p_data || !p_size )
	{
		/** At east one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_pkt_fields_out;
	}
	/** Is it first packet ? */
	if( TRUE == sp_context.sup.first_pkt )
	{
		/** Check mode */
		if( ( N_SP_MODE_RMA != sp_context.sup.rx_hdr.packet_type ) &&
			( N_SP_MODE_NORMAL != sp_context.sup.rx_hdr.packet_type ) )
		{
			/** Unknown value thus error */
			err = N_SP_ERR_SUP_NET_BAD_CONFIG;
			goto sp_sup_pkt_fields_out;
		}
		else if( sp_context.sup.rx_hdr.packet_number )
		{
			/** SUP packet number must start from '0' */
			err = N_SP_ERR_SUP_NET_WRONG_PACKET_NB;
			goto sp_sup_pkt_fields_out;
		}
		/** Save mode */
		sp_context.sup.mode = (e_sp_sup_mode)sp_context.sup.rx_hdr.packet_type;
		/** Save first packet number */
		sp_context.sup.current_packet_nb = 0;
		/** Save payload size to be received */
		sp_context.sup.lasting_packet_len = sp_context.sup.rx_hdr.packet_length;
	}
	else if( ( ( sp_context.sup.current_packet_nb + 1 ) != sp_context.sup.rx_hdr.packet_number ) ||
			( sp_context.sup.mode != (e_sp_sup_mode)sp_context.sup.rx_hdr.packet_type ) )
	{
		/** Shouldn't be there */
		err = N_SP_ERR_SUP_NET_UNKNOWN;
		goto sp_sup_pkt_fields_out;
	}
	else
	{
		/** Not the first packet */
		/** Mode is unchanged */
		/** Increment saved packet number */
		sp_context.sup.current_packet_nb++;
		/** Save payload size to be received */
		sp_context.sup.lasting_packet_len = sp_context.sup.rx_hdr.packet_length;
	}
	/** Is there a payload ? */
	if( C_SP_SUP_PAYLOAD_MIN_SIZE <= sp_context.sup.rx_hdr.packet_length )
	{
		/** Update packet reception state */
		sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_HDR_PKT;
		*p_data += ( sizeof(sp_context.sup.rx_hdr.packet_number) +
						sizeof(sp_context.sup.rx_hdr.last_packet) +
						sizeof(sp_context.sup.rx_hdr.packet_type) +
						sizeof(sp_context.sup.rx_hdr.packet_length) );
		/** Size : Command type (32bits) + Command length (32bits) + address (32bits) */
		*p_size = ( sizeof(sp_context.sup.rx_hdr.command_type) +
					sizeof(sp_context.sup.rx_hdr.command_length) +
					sizeof(sp_context.sup.rx_hdr.address) );

		/** No error */
		err = NO_ERROR;
	}
	else
	{
		/** No payload, it's an error case */
		err = N_SP_ERR_SUP_PAYLOAD_SIZE_TOO_SMALL;
	}
sp_sup_pkt_fields_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_cmd_hdr(uint8_t **p_data, uint32_t *p_size)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointers - don't care about '*p_data' to be null */
	if( !p_data || !p_size )
	{
		/** At east one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Be ready to receive segment payload if any */
		switch( sp_context.sup.rx_hdr.command_type )
		{
			case N_SP_SUP_SEGMENT_TYPE_COPY:
			{
				volatile uint_pltfrm				addr = (volatile uint32_t)sp_context.sup.rx_hdr.address;

				/** 'length' is given for all payload, don't forget to remove 32bits for 'address' from packet payload */
				*p_size = sp_context.sup.rx_hdr.command_length - sizeof(uint32_t);
				/** Check boundaries */
				if( ( (volatile uint_pltfrm)&__sbrm_free_start_addr <= addr ) && ( (volatile uint_pltfrm)&__sbrm_free_end_addr > ( addr + *p_size ) ) )
				{
					/** Data to copy is in range */
					*p_data = (uint8_t*)addr;
					sp_context.sup.payload.p_data = *p_data;
					sp_context.sup.payload.size = *p_size;
					/** Prepare next step */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_PAYLOAD;
					/** No error */
					err = NO_ERROR;
				}
				else
				{
					/** Data will not fit into internal RAM */
					err = N_SP_ERR_SUP_NO_MORE_MEMORY;
					sp_context.sup.payload.p_data = 0;
					sp_context.sup.payload.size = 0;
				}
				break;
			}
			case N_SP_SUP_SEGMENT_TYPE_WRITECSK:
			{
				/** Specific address value to indicate that CSK must be programmed in last slot */
				if ( C_SP_SUP_CSK_LAST_SLOT_ADDR == sp_context.sup.rx_hdr.address)
				{
					/** CSK must be written in last slot */
					sp_context.csk_last_slot = TRUE;
				}
				else
				{
					/** CSK must be written in first free slot */
					sp_context.csk_last_slot = FALSE;
				}
				*p_data = (uint8_t*)work_buf;
				/** 'command_length' is given in Bytes, but subtract size of address field (32bits) */
				*p_size = ( sp_context.sup.rx_hdr.command_length - sizeof(uint32_t) );
				/** 'address' field of segment type structure holds address to work buffer */
				sp_context.sup.payload.p_data = (uint8_t*)work_buf;
				sp_context.sup.payload.size = *p_size;
				/** Prepare next step */
				sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_PAYLOAD;
				/** No error */
				err = NO_ERROR;
				break;
			}
			case N_SP_SUP_SEGMENT_TYPE_GETINFO:
				if( sp_context.sup.rx_hdr.command_length )
				{
					/** must be null, therefore it's an error */
					err = N_SP_ERR_SUP_WRONG_CMD_LENGTH;
				}
				else
				{
					/** 'get-info' command is special because it has no 'address' field.
					 * As a consequence, next step length must be shortened with 4 Bytes.
					 * And it corresponds to either 1 Byte of UID, or 'Number of signatures' field. */
					/** Update temporary pointers */
					*p_size = sp_context.sup.lasting_packet_len;
					/** 'address' field comes from previous reception state */
					*((uint32_t*)&sp_context.security.uid[0]) = sp_context.sup.rx_hdr.address;
					/** An 32bits has been already received ... 'address' field ... thus we point on next index*/
					*p_data = (uint8_t*)&sp_context.security.uid[sizeof(uint32_t)];
					sp_context.sup.payload.p_data = sp_context.security.uid;
					sp_context.sup.payload.size = *p_size + sizeof(uint32_t);
					sp_context.security.total_size = sp_context.sup.payload.size;
					/** Prepare next step */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SECU_SIG;
					/** No error */
					err = NO_ERROR;
				}
				break;
			case N_SP_SUP_SEGMENT_TYPE_EXECUTE:
				/** Here 'work_buf' is used as temporary buffer */
				*p_data = (uint8_t*)work_buf;
				/** 'length' is given in 32bits words */
				*p_size = ( sp_context.sup.rx_hdr.command_length - sizeof(uint32_t) );
				sp_context.sup.payload.p_data = *p_data;
				sp_context.sup.payload.size = *p_size;
				/** Prepare next step */
				sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SEG_PAYLOAD;
				/** No error */
				err = NO_ERROR;
				break;
			default:
				/** Error should not happen */
				err = N_SP_ERR_SUP_WRONG_CMD;
				break;
		}
	}
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_secu(t_context *p_ctx, uint8_t **p_data, uint32_t *p_size)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;

	/** Check input pointers - don't care about '*p_data' to be null */
	if( !p_data || !p_size || !p_ctx )
	{
		/** At east one pointer is null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Verify UID if present */
		if( N_SP_MODE_RMA == sp_context.sup.mode )
		{
			/** To retrieve UID */
			t_sbrm_context							*p_sbrm_ctx = (t_sbrm_context*)p_ctx->p_sbrm_context;

			/** Get UID */
			err = sbrm_read_otp(p_ctx, C_OTP_UID_OFST, p_sbrm_ctx->uid, C_OTP_UID_SIZE);
			if( err )
			{
				/** OTP can't be read */
				goto sp_sup_secu_out;
			}
			/** Read platform's UID from OTP */
			err = memcmp((const void*)p_sbrm_ctx->uid, (const void*)sp_context.security.uid, C_UID_SIZE_IN_BYTES);
			if( err )
			{
				/** UIDs do not match, packet does not target current platform */
				err = N_SP_ERR_SUP_UID_NO_MATCH;
				goto sp_sup_secu_out;
			}
			else
			{
				/** No error for now - just to update the variable at this step */
				err = NO_ERROR;
			}
		}
		/** Packet must have, at least one signature */
		if( !sp_context.security.nb_signatures || ( C_SP_SUP_MAX_SIGNATURE_ELMNT_NB < sp_context.security.nb_signatures ) )
		{
			/** Signatures number does not fit */
			err = N_SP_ERR_SUP_PACKET_REJECTED;
		}
		else
		{
			/** Now parameter(s) is(are) ok */
			err = NO_ERROR;
		}
	}
sp_sup_secu_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_receive_packet(void *p_ctx)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint32_t									i;
	uint32_t									size_read = sizeof(sp_context.sup.rx_hdr.htt_magic_word);
	uint8_t										*p_tmp;
	t_context									*p_context;


	/** Check input pointer */
	if( !p_ctx )
	{
		/** Pointer must not be null */
		err = GENERIC_ERR_NULL_PTR;
		goto sp_sup_receive_packet_out;
	}
	/** Assign pointer */
	p_context = (t_context*)p_ctx;
	/** Initialize variables */
	sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SYNC;
	sp_context.state = N_SP_STATE_SUP_RECEPTION;
	p_tmp = (uint8_t*)&sp_context.sup.rx_hdr;
	/** Set variable to enter the loop */
	err = NO_ERROR;
	/** Loop to receive packet */
	while( ( N_SP_STATE_END > sp_context.state ) && ( NO_ERROR == err ) )
	{
		/** Read expected number of bytes */
		err = sp_uart_receive_buffer(p_ctx, (uint8_t*)p_tmp, (uint32_t*)&size_read);
		/**  */
		switch( sp_context.sup.state_pkg )
		{
			case N_SP_SUP_RCV_PKT_SYNC:
				/** Check session ID */
				if ( err )
				{
					/** Any other error will lead to exit from SUP */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				/** First read directly into HTT field */
				else if( ( NO_ERROR == err ) && ( C_SP_HTT_MAGIC_WORD == sp_context.sup.rx_hdr.htt_magic_word ) )
				{
					/** Good to go ... */
					/** No error then keep going */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SESSIONID;
					/** Point on appropriate buffer with appropriate size */
					p_tmp = (uint8_t*)&sp_context.sup.rx_hdr.session_id;
					size_read = sizeof(sp_context.sup.rx_hdr.session_id);
					/** No error */
				}
				else if( NO_ERROR == err )
				{
					/** Try to re-synchronize */
					p_tmp[0] = p_tmp[1];
					p_tmp[1] = p_tmp[2];
					p_tmp[2] = p_tmp[3];
					p_tmp = (uint8_t*)&p_tmp[3];
					/** Read only next character */
					size_read = 1;
					/** If here, therefore synchronization pattern has not been found */
					/** Wait for next character */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SYNC;
					/** No error */
					err = NO_ERROR;
				}
				break;
			case N_SP_SUP_RCV_PKT_SESSIONID:
				/** Check session ID */
				if ( err )
				{
					/** Any other error will lead to exit from SUP */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else if( TRUE == sp_context.sup.first_pkt )
				{
					/** If this packet is the first one, variable will be updated only when packet
					 * is checked ok */
					/** No error then keep going */
					/** Update saved session identifier */
					sp_context.sup.current_session_id = sp_context.sup.rx_hdr.session_id;
					/** Update packet reception state */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_FIELDS;
					/** Update data pointer and size */
					p_tmp = (uint8_t*)&sp_context.sup.rx_hdr.packet_number;
					size_read = ( sizeof(sp_context.sup.rx_hdr.packet_number) +
									sizeof(sp_context.sup.rx_hdr.last_packet) +
									sizeof(sp_context.sup.rx_hdr.packet_type) +
									sizeof(sp_context.sup.rx_hdr.packet_length) );
				}
				else if( sp_context.sup.current_session_id == sp_context.sup.rx_hdr.session_id )
				{
					/** No error then keep going */
					/** Update packet reception state */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_FIELDS;
					/** Update data pointer and size */
					p_tmp = (uint8_t*)&sp_context.sup.rx_hdr.packet_number;
					size_read = ( sizeof(sp_context.sup.rx_hdr.packet_number) +
									sizeof(sp_context.sup.rx_hdr.last_packet) +
									sizeof(sp_context.sup.rx_hdr.packet_type) +
									sizeof(sp_context.sup.rx_hdr.packet_length) );
				}
				else
				{
					/** Problem, then stop communication */
					err = N_SP_ERR_SUP_NET_WRONG_SESSION;
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				break;
			case N_SP_SUP_RCV_PKT_FIELDS:
				/** Check if error in receiving data */
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				/** Packet fields have been received so let's analyze them */
				/** Here is first packet */
				else
				{
					/** Prepare next step */
					err = sp_sup_pkt_fields((uint8_t**)&p_tmp, (uint32_t*)&size_read);
					if( err )
					{
						/** Error should not happen */
						sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
						sp_context.state = N_SP_STATE_END;
					}
				}
				break;
			case N_SP_SUP_RCV_PKT_SEG_HDR_PKT:
				/** Check if error in receiving data */
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else
				{
					/** Update lasting packet length */
					sp_context.sup.lasting_packet_len -= size_read;
					/**  */
					err = sp_sup_cmd_hdr((uint8_t**)&p_tmp, (uint32_t*)&size_read);
					if( err )
					{
						/** Error should not happen */
						sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
						sp_context.state = N_SP_STATE_END;
					}
				}
				break;
			case N_SP_SUP_RCV_PKT_SEG_PAYLOAD:
				/** Check if error in receiving data */
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else
				{
					/** Update lasting packet length, and it lasts only security part */
					sp_context.sup.lasting_packet_len -= size_read;
					/** Prepare next step */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_SECU_SIG;
					/** Update temporary pointers */
					size_read = sp_context.sup.lasting_packet_len;
					sp_context.security.total_size = size_read;
					p_tmp = (uint8_t*)sp_context.security.uid;
				}
				break;
			case N_SP_SUP_RCV_PKT_SECU_SIG:
				if( err )
				{
					/** Error should not happen */
					sp_context.sup.state_pkg = N_SP_SUP_RCV_PKT_END;
					sp_context.state = N_SP_STATE_END;
				}
				else
				{
					/** Check signature */
					err = sp_sup_secu(p_ctx, (uint8_t**)&p_tmp, (uint32_t*)&size_read);
					if ( err )
					{
						/** Something goes wrong with security checks */
						err = N_SP_ERR_RESET_PLATFORM;
						goto sp_sup_receive_packet_out;
					}
					/** If OK, then whatever packet it is, it's no more first one */
					sp_context.sup.first_pkt = FALSE;
					/** Update global state */
					sp_context.state = N_SP_STATE_POST_PROCESS;
					/** Check if it is the last packet */
					/** Ok then packet has been received */
					sp_context.state = N_SP_STATE_END;
					sp_context.sup.lasting_packet_len = 0;
					/** No error, just to be sure */
					err = NO_ERROR;
				}
				break;
			case N_SP_SUP_RCV_PKT_END:
			default:
				goto sp_sup_receive_packet_out;
		}
	}
sp_sup_receive_packet_out:
	/** Stop bus reception */
	/** Disable UART interruption */
	M_UART_MASK_RX_IRQ(sp_context.port.uart.reg_uart);
	/** Disable UART's RX */
	M_UART_RX_DISABLE(sp_context.port.uart.reg_uart);
	/** End Of Function */
	return err;
}

/******************************************************************************/
int_pltfrm sp_sup_packet_response(t_context *p_ctx,
								uint32_t error,
								uint32_t session_id,
								uint32_t packet_number,
								uint8_t *p_data,
								uint32_t length)
{
	int_pltfrm 									err = GENERIC_ERR_UNKNOWN;
	uint32_t									crc;

	/** Check parameters in special case where there's data to send */
	if( !p_ctx || ( !p_data && length ) )
	{
		/** Pointer should not have been null */
		err = GENERIC_ERR_NULL_PTR;
	}
	else
	{
		/** Prepare TX packet header */
		sp_context.sup.tx_hdr.sesion_id = session_id;
		sp_context.sup.tx_hdr.packet_number = packet_number;
		sp_context.sup.tx_hdr.tth_magic_word = C_SP_TTH_MAGIC_WORD;
		sp_context.sup.tx_hdr.ret_error = error;
		sp_context.sup.tx_hdr.data_length = length;
		/** Given 'length' with 'error' size - 32bits, 'data length' size - 32bits and 'crc' size - 32bits */
		sp_context.sup.tx_hdr.packet_length = sp_context.sup.tx_hdr.data_length + ( 3 * sizeof(uint32_t) );
		/** Zero-ize 'crc' buffer */
		crc = 0;
		/** CRC computation */
		/** Header */
		err = sbrm_compute_crc((uint32_t*)&crc, (uint8_t*)&sp_context.sup.tx_hdr, sizeof(t_sp_sup_tx_pckt_hdr));
		if( err )
		{
			/** Error should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_sup_packet_response_out;
		}
		/** Payload - other if any */
		if( length )
		{
			err = sbrm_compute_crc((uint32_t*)&crc, (uint8_t*)p_data, length);
			if( err )
			{
				/** Error should not happen */
				err = GENERIC_ERR_CRITICAL;
				goto sp_sup_packet_response_out;
			}
		}
		/** Now start sending ... */
		/** ... with header ... */
		err = sp_uart_send_buffer(p_ctx, (uint8_t*)&sp_context.sup.tx_hdr, sizeof(t_sp_sup_tx_pckt_hdr));
		if( err )
		{
			/** Error should not happen */
			err = GENERIC_ERR_CRITICAL;
			goto sp_sup_packet_response_out;
		}
		/** ... then payload if any */
		if ( length )
		{
			err = sp_uart_send_buffer(p_ctx, (uint8_t*)p_data, length);
			if( err )
			{
				/** Error should not happen */
				err = GENERIC_ERR_CRITICAL;
				goto sp_sup_packet_response_out;
			}
		}
		/** ... and finish with CRC */
		err = sp_uart_send_buffer(p_ctx, (uint8_t*)&crc, sizeof(uint32_t));
		if( err )
		{
			/** Error should not happen */
			err = GENERIC_ERR_CRITICAL;
		}
	}
sp_sup_packet_response_out:
	/** End Of Function */
	return err;
}

/******************************************************************************/
/* End Of File */
