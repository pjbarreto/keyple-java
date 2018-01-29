package org.keyple.seproxy;

import java.util.List;

/**
 * The Class SEResponse. This class aggregates the elements of a response from a
 * local or remote SE Reader, received through a ProxyReader, including a group
 * of APDU responses and the previous status of the logical channel with the
 * targeted SE application.
 *
 * @author Ixxi
 */
public class SeResponse {

    /**
     * is defined as true by the SE reader in case a logical channel was already
     * open with the target SE application.
     */
    private boolean channelPreviouslyOpen;

    /**
     * present if channelPreviouslyOpen is false, contains the FCI response of
     * the channel opening (either the response of a SelectApplication command,
     * or the response of a GetData(‘FCI’) command).
     */
    private ApduResponse fci;

    /**
     * could contain a group of APDUResponse returned by the selected SE
     * application on the SE reader.
     */
    private List<ApduResponse> apduResponses;

    /**
     * present if channelPreviouslyOpen is false and if the SE Reader manages
     * the ATR (as for ISO 7816-3 contacts reader, or B’ Innovatron contactless
     * reader), contains the ATR.
     */
    private byte[] atr;

    /**
     * the constructor called by a ProxyReader during the processing of the
     * ‘transmit’ method.
     *
     * @param channelPreviouslyOpen
     *            the channel previously open
     * @param fci
     *            the fci data
     * @param apduResponses
     *            the apdu responses
     */
    public SeResponse(boolean channelPreviouslyOpen, ApduResponse fci, List<ApduResponse> apduResponses) {
        this.channelPreviouslyOpen = channelPreviouslyOpen;

        this.fci = fci;

        this.apduResponses = apduResponses;
    }

    /**
     * the constructor called by a ProxyReader during the processing of the
     * ‘transmit’ method.
     *
     * @param channelPreviouslyOpen
     *            the channel previously open
     * @param fci
     *            the fci data
     * @param apduResponses
     *            the apdu responses
     * @param atr
     *            the atr
     */
    public SeResponse(boolean channelPreviouslyOpen, ApduResponse fci, List<ApduResponse> apduResponses, byte[] atr) {
        this.channelPreviouslyOpen = channelPreviouslyOpen;
        this.fci = null;
        this.atr = null;
        this.fci = fci;
        this.atr = atr;
        this.apduResponses = apduResponses;
    }

    /**
     * Was channel previously open.
     *
     * @return the previous state of the logical channel.
     */
    public boolean wasChannelPreviouslyOpen() {
        return channelPreviouslyOpen;
    }

    /**
     * Gets the fci data.
     *
     * @return null or the FCI response if a channel was opened.
     */
    public ApduResponse getFci() {
        return this.fci;
    }

    /**
     * Gets the apdu responses.
     *
     * @return the group of APDUs responses returned by the SE application for
     *         this instance of SEResponse.
     */
    public List<ApduResponse> getApduResponses() {
        return apduResponses;
    }

    /**
     * returns null or the ATR if ATR is supported by the SE Reader and if a
     * channel was opened
     *
     * @return the ATR
     */
    public byte[] getAtr() {
        return this.atr;
    }
}