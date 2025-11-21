// dMail v2 UI update: use append-only mailbox indexes + resolver roots.
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import {
  appendInboxEntry,
  appendSentEntry,
  decryptEmail,
  encryptEmail,
  fetchAttachment,
  synapseFetch,
  synapseUpload,
  loadMailboxFromCid,
  createEmptyCalendar,
  appendCalendarEvent,
  loadCalendarFromCid as loadCalendarFromCidFile,
  persistCalendar,
  getCalendarUploadResult,
  setCalendarUploadResult,
  generateCalendarIcs,
  resolvePublicKey,
  resolveMailboxRoot,
  normalizeMailboxRoot,
  getMailboxIndexPointer,
  signEnvelope,
  computeEnvelopeMetadataHash,
  verifyEnvelopeSignature,
  getMailboxEntries,
  ensureRegisteredIdentity,
} from '@dmail/core'

import CalendarSidebar from './components/calendar/CalendarSidebar'
import EventModal from './components/calendar/EventModal'

import './App.css'
import { clearIdentityCache, getOrCreateIdentityCached } from './utils/identityCache'

const FALLBACK_SEPOLIA_RPC_URL = 'https://ethereum-sepolia-rpc.publicnode.com'
const SEPOLIA_CHAIN_ID_HEX = '0xaa36a7'
function stringToBase64(value) {
  if (typeof window !== 'undefined' && window.btoa) {
    return window.btoa(unescape(encodeURIComponent(value)))
  }
  if (typeof globalThis !== 'undefined' && globalThis.Buffer) {
    return globalThis.Buffer.from(value, 'utf8').toString('base64')
  }
  throw new Error('Base64 encoding is not supported in this environment')
}

function getBrowserHostname() {
  if (typeof window !== 'undefined' && window.location) {
    return window.location.hostname
  }
  return undefined
}

function App() {
  const [walletAddress, setWalletAddress] = useState(null)
  const [ensName, setEnsName] = useState(null)
  const [provider, setProvider] = useState(null)
  const [statusMessage, setStatusMessage] = useState('')
  const [errorMessage, setErrorMessage] = useState('')
  const [identityPublicKey, setIdentityPublicKey] = useState(null)
  const [mailboxUploadResult, setMailboxUploadResultState] = useState(null)
  const [mailboxRoot, setMailboxRoot] = useState(null)
  const [mailboxEntries, setMailboxEntries] = useState([])
  const [sentEntries, setSentEntries] = useState([])
  const [loadingInbox, setLoadingInbox] = useState(false)
  const [selectedEmail, setSelectedEmail] = useState(null)
  const [sending, setSending] = useState(false)
  const [showCompose, setShowCompose] = useState(false)
  const [activeView, setActiveView] = useState('inbox')
  const [searchQuery, setSearchQuery] = useState('')
  const [calendarFullPage, setCalendarFullPage] = useState(false)
  const [fetchingPubKey, setFetchingPubKey] = useState(false)
  const [pubKeyFetchError, setPubKeyFetchError] = useState(null)
  const [showManualPubKey, setShowManualPubKey] = useState(false)
  const [composeState, setComposeState] = useState({
    to: '',
    subject: '',
    message: '',
    recipientPublicKey: '',
    attachments: [],
  })
  const [calendarEvents, setCalendarEvents] = useState([])
  const [calendarUploadResult, setCalendarUploadResultState] = useState(null)
  const [calendarLoading, setCalendarLoading] = useState(false)
  const [calendarError, setCalendarError] = useState('')
  const [showEventModal, setShowEventModal] = useState(false)
  const [savingEvent, setSavingEvent] = useState(false)
  const [identityDeriving, setIdentityDeriving] = useState(false)
  const [identityStatusMessage, setIdentityStatusMessage] = useState('')
  const identityMaterialRef = useRef(null)
  const identityEnsRef = useRef(null)

  const evaluateEntrySignature = useCallback(
    (entry) => {
      if (!entry?.signature || !entry?.signerPublicKey) {
        return null
      }
      try {
        const metadataHash = computeEnvelopeMetadataHash(entry)
        const valid = verifyEnvelopeSignature(entry.signerPublicKey, entry.signature, metadataHash)
        return valid
      } catch (error) {
        console.warn('Failed to verify email signature for entry', entry?.messageId ?? entry?.cid, error)
        return false
      }
    },
    []
  )

  const annotateEntriesWithSignature = useCallback(
    (entries) =>
      entries.map((entry) => ({
        ...entry,
        _signatureValid: evaluateEntrySignature(entry),
      })),
    [evaluateEntrySignature]
  )

  const sepoliaRpcUrl = useMemo(
    () =>
      import.meta.env.VITE_ETH_RPC_URL ??
      import.meta.env.VITE_SEPOLIA_RPC_URL ??
      FALLBACK_SEPOLIA_RPC_URL,
    []
  )

  const ensureSepoliaChain = useCallback(async () => {
    if (!window.ethereum?.request) {
      throw new Error('MetaMask (window.ethereum) not available for ENS operations.')
    }
    const currentChainId = await window.ethereum.request({ method: 'eth_chainId' })
    if (currentChainId === SEPOLIA_CHAIN_ID_HEX) {
      return false
    }
    try {
      await window.ethereum.request({
        method: 'wallet_switchEthereumChain',
        params: [{ chainId: SEPOLIA_CHAIN_ID_HEX }],
      })
      return true
    } catch (switchError) {
      if (switchError?.code === 4902) {
        await window.ethereum.request({
          method: 'wallet_addEthereumChain',
          params: [
            {
              chainId: SEPOLIA_CHAIN_ID_HEX,
              chainName: 'Sepolia test network',
              nativeCurrency: { name: 'Sepolia ETH', symbol: 'ETH', decimals: 18 },
              rpcUrls: [sepoliaRpcUrl],
              blockExplorerUrls: ['https://sepolia.etherscan.io/'],
            },
          ],
        })
        return true
      }
      throw new Error('Please switch MetaMask to the Sepolia testnet before sending mail.')
    }
  }, [sepoliaRpcUrl])

  const ensureProvider = useCallback(async () => {
    if (!window.ethereum) {
      throw new Error('MetaMask (window.ethereum) not available')
    }
    const switched = await ensureSepoliaChain()
    if (!provider || switched) {
      const { BrowserProvider } = await import('ethers')
      const browserProvider = new BrowserProvider(window.ethereum)
      setProvider(browserProvider)
      return browserProvider
    }
    return provider
  }, [provider, ensureSepoliaChain])

  // Create a Sepolia provider specifically for ENS resolution
  const getEnsProvider = useCallback(async () => {
    const { JsonRpcProvider } = await import('ethers')
    return new JsonRpcProvider(sepoliaRpcUrl)
  }, [sepoliaRpcUrl])

  // Function to resolve ENS name for current address
  const resolveEnsName = useCallback(
    async (address) => {
      if (!address) return null

      try {
        // Use Sepolia provider for ENS resolution (ENS names are on Sepolia testnet)
        const ensProvider = await getEnsProvider()
        console.log('Resolving ENS on Sepolia for address:', address)
        
        const name = await ensProvider.lookupAddress(address)
        console.log('ENS reverse lookup result:', name)
        
        if (name) {
          // Verify forward resolution
          try {
            const resolvedAddress = await ensProvider.resolveName(name)
            if (resolvedAddress && resolvedAddress.toLowerCase() === address.toLowerCase()) {
              console.log('✓ ENS name verified:', name, '->', resolvedAddress)
              return name
            } else {
              console.warn('⚠ ENS forward resolution mismatch:', name, 'resolved to', resolvedAddress, 'expected', address)
              return name // Still return it, just warn
            }
          } catch (verifyError) {
            console.warn('⚠ Failed to verify ENS name:', verifyError)
            return name // Still return it if reverse lookup worked
          }
        } else {
          console.warn('⚠ No reverse ENS record found for:', address)
          return null
        }
      } catch (error) {
        console.error('❌ Failed to lookup ENS name:', error)
        return null
      }
    },
    [getEnsProvider]
  )

  const ensureRegisteredIdentityIfNeeded = useCallback(
    async (targetEns, derivedIdentity, signer) => {
      if (!targetEns || !derivedIdentity?.x25519PublicBase64 || !targetEns.endsWith('.eth')) {
        return false
      }
      try {
        const ensProvider = await getEnsProvider()
        if (ensProvider) {
          try {
            const existing = await resolvePublicKey(targetEns, {
              provider: ensProvider,
              ensName: targetEns,
            })
            if (existing === derivedIdentity.x25519PublicBase64) {
              return false
            }
          } catch (lookupError) {
            console.warn('Resolver lookup failed while checking identity registration', lookupError)
          }
        }
        await ensureRegisteredIdentity(targetEns, derivedIdentity.x25519PublicBase64, signer)
        return true
      } catch (registrationError) {
        console.warn('Failed to register identity with resolver', registrationError)
        throw registrationError
      }
    },
    [getEnsProvider]
  )

  const deriveIdentityMaterial = useCallback(
    async (ensOverride) => {
      const targetIdentifier = ensOverride ?? ensName ?? walletAddress ?? null
      if (!walletAddress) {
        identityMaterialRef.current = null
        identityEnsRef.current = null
        setIdentityPublicKey(null)
        setIdentityStatusMessage('')
        return null
      }
      try {
        setIdentityDeriving(true)
        setIdentityStatusMessage('Generating dMail identity...')
        const providerInstance = await ensureProvider()
        const signer = await providerInstance.getSigner()
        let signerAddress = null
        try {
          signerAddress = (await signer.getAddress())?.toLowerCase() ?? null
        } catch (addressError) {
          console.warn('Unable to read signer address for identity cache key', addressError)
        }
        const derived = await getOrCreateIdentityCached({
          signer,
          account: signerAddress ?? walletAddress?.toLowerCase(),
          domain: getBrowserHostname(),
        })
        identityMaterialRef.current = {
          privateKey: derived.x25519PrivateBase64,
          publicKey: derived.x25519PublicBase64,
          senderStaticSymKey: derived.senderStaticSymKeyBase64,
          signingKey: derived.signingKeyBase64,
          signingPublicKey: derived.signingPublicKeyBase64,
        }
        identityEnsRef.current = targetIdentifier
        setIdentityPublicKey(derived.x25519PublicBase64)
        if (targetIdentifier) {
          try {
            setIdentityStatusMessage('Checking resolver registration...')
            const registered = await ensureRegisteredIdentityIfNeeded(
              targetIdentifier,
              derived,
              signer
            )
            setIdentityStatusMessage(
              registered
                ? 'Identity registered with ENS resolver.'
                : 'Identity stored in your browser.'
            )
          } catch (registrationError) {
            setIdentityStatusMessage(
              registrationError.message ?? 'Resolver registration failed.'
            )
          }
        } else {
          setIdentityStatusMessage('Identity stored in your browser.')
        }
        return identityMaterialRef.current
      } catch (error) {
        console.warn('Failed to derive identity from wallet', error)
        setIdentityStatusMessage(error.message ?? 'Failed to derive identity.')
        return null
      } finally {
        setIdentityDeriving(false)
      }
    },
    [walletAddress, ensName, ensureProvider, ensureRegisteredIdentityIfNeeded]
  )

  const ensureIdentityMaterial = useCallback(
    async (ensOverride) => {
      const targetEns = ensOverride ?? ensName ?? walletAddress ?? null
      if (
        identityMaterialRef.current &&
        identityMaterialRef.current.publicKey &&
        identityEnsRef.current === targetEns
      ) {
        return identityMaterialRef.current
      }
      return await deriveIdentityMaterial(targetEns)
    },
    [deriveIdentityMaterial, ensName]
  )

  const handleRegenerateIdentity = useCallback(async () => {
    if (!walletAddress) {
      setStatusMessage('Connect wallet to derive identity first.')
      return
    }
    const domain = getBrowserHostname()
    clearIdentityCache(walletAddress?.toLowerCase(), domain)
    identityMaterialRef.current = null
    identityEnsRef.current = null
    setIdentityPublicKey(null)
    await deriveIdentityMaterial(ensName)
  }, [walletAddress, ensName, deriveIdentityMaterial])

  // Listen for account changes and re-resolve ENS
  useEffect(() => {
    if (!window.ethereum || !walletAddress) return

    const handleAccountsChanged = async (accounts) => {
      if (accounts.length > 0 && accounts[0] !== walletAddress) {
        console.log('Account changed to:', accounts[0])
        const newAddress = accounts[0]
        setWalletAddress(newAddress)
        
        // Resolve ENS name using Sepolia provider
        const name = await resolveEnsName(newAddress)
        setEnsName(name)
      } else if (accounts.length === 0) {
        console.log('Wallet disconnected')
        setWalletAddress(null)
        setEnsName(null)
      }
    }

    window.ethereum.on('accountsChanged', handleAccountsChanged)

    return () => {
      window.ethereum?.removeListener('accountsChanged', handleAccountsChanged)
    }
  }, [walletAddress, resolveEnsName])

  useEffect(() => {
    if (!walletAddress) {
      identityMaterialRef.current = null
      identityEnsRef.current = null
      setIdentityPublicKey(null)
      return
    }
    void deriveIdentityMaterial(ensName)
  }, [walletAddress, ensName, deriveIdentityMaterial])

  useEffect(() => {
    if (typeof window === 'undefined' || !window.ethereum) {
      return
    }
    let cancelled = false
    const autoConnect = async () => {
      try {
        const { BrowserProvider } = await import('ethers')
        const browserProvider = new BrowserProvider(window.ethereum)
        const accounts = await browserProvider.send('eth_accounts', [])
        if (!accounts?.length || cancelled) {
          return
        }
        const address = accounts[0]
        setWalletAddress(address)
        const resolvedName = await resolveEnsName(address)
        setEnsName(resolvedName)
        await deriveIdentityMaterial(resolvedName)
      } catch (error) {
        console.warn('Auto-connect skipped', error)
      }
    }
    void autoConnect()
    return () => {
      cancelled = true
    }
  }, [deriveIdentityMaterial, resolveEnsName])

  const connectWallet = useCallback(async () => {
    try {
      setErrorMessage('')
      const browserProvider = await ensureProvider()
      const accounts = await browserProvider.send('eth_requestAccounts', [])
      const address = accounts?.[0]
      if (!address) throw new Error('No accounts returned from provider')
      setWalletAddress(address)
      
      // Resolve ENS name using Sepolia provider (ENS names are on Sepolia testnet)
      const resolvedName = await resolveEnsName(address)
      setEnsName(resolvedName)
      
      // Don't show toast - status is shown in navbar
      return browserProvider
    } catch (error) {
      console.error(error)
      setErrorMessage(error.message ?? 'Failed to connect wallet')
      return null
    }
  }, [ensureProvider, resolveEnsName])

  const updateCompose = (changes) => {
    setComposeState((prev) => ({
      ...prev,
      ...changes,
    }))
  }

  // Auto-fetch public key from ENS when recipient changes
  const fetchRecipientPublicKey = useCallback(
    async (ensName) => {
      if (!ensName || !ensName.endsWith('.eth')) {
        setPubKeyFetchError(null)
        setShowManualPubKey(false)
        updateCompose({ recipientPublicKey: '' })
        return
      }

      setFetchingPubKey(true)
      setPubKeyFetchError(null)
      setShowManualPubKey(false)

      try {
        const ensProvider = await getEnsProvider()
        const publicKey =
          (await resolvePublicKey(ensName, { provider: ensProvider, ensName })) ?? null
        
        if (publicKey) {
          updateCompose({ recipientPublicKey: publicKey })
          setPubKeyFetchError(null)
        } else {
          setPubKeyFetchError(
            `No resolver profile found for ${ensName}. Ask the recipient to open dMail v2 once to onboard automatically.`
          )
          setShowManualPubKey(true)
          updateCompose({ recipientPublicKey: '' })
        }
      } catch (error) {
        console.warn('Failed to fetch public key from ENS:', error)
        setPubKeyFetchError(`Could not fetch public key for ${ensName}. You can enter it manually.`)
        setShowManualPubKey(true)
        updateCompose({ recipientPublicKey: '' })
      } finally {
        setFetchingPubKey(false)
      }
    },
    [getEnsProvider]
  )

  const refreshInbox = useCallback(async () => {
    setLoadingInbox(true)
    setErrorMessage('')
    try {
      await ensureProvider()
      const ensProvider = await getEnsProvider()
      const targetEns =
        ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)
      const ownerIdentifier = targetEns ?? walletAddress
      const mailboxRootResponse = await resolveMailboxRoot(ownerIdentifier, {
        provider: ensProvider,
      })
      const normalizedRoot = normalizeMailboxRoot(mailboxRootResponse, { owner: ownerIdentifier })
      setMailboxRoot(normalizedRoot)

      const inboxPointer = getMailboxIndexPointer(normalizedRoot, 'inbox')
      const sentPointer = getMailboxIndexPointer(normalizedRoot, 'sent')
      setMailboxUploadResultState(inboxPointer ?? null)

      if (!inboxPointer?.cid && !sentPointer?.cid) {
        setMailboxEntries([])
        setSentEntries([])
        setStatusMessage('No mailbox found for this account yet')
        return
      }

      const [inboxMailbox, sentMailbox] = await Promise.all([
        inboxPointer?.cid
          ? loadMailboxFromCid(inboxPointer, { optional: true })
          : Promise.resolve(null),
        sentPointer?.cid
          ? loadMailboxFromCid(sentPointer, { optional: true })
          : Promise.resolve(null),
      ])

      const inboxEntriesList = annotateEntriesWithSignature(getMailboxEntries(inboxMailbox))
      const sentEntriesList = annotateEntriesWithSignature(
        getMailboxEntries(sentMailbox).filter((entry) => entry.cidSender)
      )
      setMailboxEntries(inboxEntriesList)
      setSentEntries(sentEntriesList)
      const total =
        getMailboxEntries(inboxMailbox).length + getMailboxEntries(sentMailbox).length
      setStatusMessage(`Loaded ${total} email(s)`)
    } catch (error) {
      console.error(error)
      setErrorMessage(error.message ?? 'Failed to load mailbox')
    } finally {
      setLoadingInbox(false)
    }
  }, [ensureProvider, ensName, getEnsProvider, walletAddress, annotateEntriesWithSignature])

  const refreshCalendar = useCallback(async () => {
    if (!walletAddress && !ensName) return

    setCalendarLoading(true)
    setCalendarError('')
    try {
      const ensProvider = await getEnsProvider()
      await ensureProvider()
      const targetEns =
        ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)
      if (!targetEns) {
        setCalendarEvents([])
        setCalendarUploadResultState(null)
        return
      }

      const uploadResult = await getCalendarUploadResult(targetEns, { provider: ensProvider })
      setCalendarUploadResultState(uploadResult ?? null)

      if (!uploadResult?.cid || !uploadResult?.pieceCid) {
        setCalendarEvents([])
        return
      }

      const calendar = await loadCalendarFromCidFile(uploadResult, { optional: true })
      setCalendarEvents(calendar?.events ?? [])
    } catch (error) {
      console.error(error)
      setCalendarError(error.message ?? 'Failed to load calendar')
    } finally {
      setCalendarLoading(false)
    }
  }, [walletAddress, ensName, getEnsProvider, ensureProvider])

  useEffect(() => {
    if (!walletAddress && !ensName) return
    void refreshInbox()
  }, [walletAddress, ensName, refreshInbox])

  useEffect(() => {
    if (!walletAddress && !ensName) return
    void refreshCalendar()
  }, [walletAddress, ensName, refreshCalendar])

  const openEmail = useCallback(
    async (entry) => {
      setSelectedEmail(null)
      setErrorMessage('')
      if (!identityMaterialRef.current?.privateKey) {
        setErrorMessage('Identity key required to decrypt emails')
        return
      }
      try {
        const folder = entry.folder ?? activeView ?? 'inbox'
        const isSentEntry = folder === 'sent'
        const cid = isSentEntry ? entry.cidSender ?? entry.cid : entry.cid ?? entry.cidRecipient
        const pieceCid = isSentEntry
          ? entry.senderPieceCid ?? entry.pieceCid ?? entry.recipientPieceCid
          : entry.pieceCid ?? entry.recipientPieceCid
        const serviceURL = isSentEntry
          ? entry.senderServiceURL ?? entry.serviceURL
          : entry.serviceURL
        const providerId = isSentEntry ? entry.senderProviderId ?? entry.providerId : entry.providerId
        const providerAddress = isSentEntry
          ? entry.senderProviderAddress ?? entry.providerAddress
          : entry.providerAddress

        if (!cid || !pieceCid || !serviceURL) {
          throw new Error('Email entry missing provider info. Cannot retrieve with Synapse-only mode.')
        }
        const providerInfo = {
          id: providerId,
          address: providerAddress,
          products: {
            PDP: {
              data: {
                serviceURL,
              }
            }
          }
        }
        const encryptedPayload = await synapseFetch(cid, {
          as: 'json',
          pieceCid,
          providerInfo
        })
        // Decrypt email and fetch attachments from Synapse
        const decrypted = await decryptEmail(
          encryptedPayload,
          {
            identityPrivateKey: identityMaterialRef.current?.privateKey ?? null,
            senderSecret: identityMaterialRef.current?.privateKey ?? null,
          },
          {
            fetchAttachmentsFromSynapse: true,
          }
        )
        let signatureValid = entry._signatureValid ?? null
        if (signatureValid === null && entry.signature && entry.signerPublicKey) {
          try {
            const metadataHash = computeEnvelopeMetadataHash(entry)
            signatureValid = verifyEnvelopeSignature(entry.signerPublicKey, entry.signature, metadataHash)
            if (signatureValid === false) {
              setStatusMessage('⚠️ Email signature invalid')
            }
          } catch (signatureError) {
            console.warn('Failed to verify email signature', signatureError)
          }
        }
        setSelectedEmail({
          entry,
          decrypted,
          encrypted: encryptedPayload,
          signatureValid,
        })
      } catch (error) {
        console.error(error)
        setErrorMessage(error.message ?? 'Failed to decrypt email. Check private key.')
      }
    },
    [activeView]
  )

  const handleAttachments = async (event) => {
    const files = Array.from(event.target.files ?? [])
    const attachments = await Promise.all(
      files.map(async (file) => ({
        filename: file.name,
        mimeType: file.type || 'application/octet-stream',
        data: await readFileAsBase64(file),
      }))
    )
    updateCompose({ attachments })
  }

  const handleShareEvent = useCallback(
    (event) => {
      if (!event) return
      const organizer = ensName ?? walletAddress ?? 'dmail-user'
      const ics = generateCalendarIcs(event, organizer)
      setComposeState({
        to: '',
        subject: `[Invite] ${event.title}`,
        message: `You're invited to ${event.title} on ${new Date(event.startTime).toLocaleString()}${
          event.location ? ` at ${event.location}` : ''
        }.\n\n${event.description ?? ''}`,
        attachments: [
          {
            filename: `${event.title || 'event'}.ics`,
            mimeType: 'text/calendar',
            data: stringToBase64(ics),
          },
        ],
        recipientPublicKey: '',
      })
      setShowCompose(true)
    },
    [ensName, walletAddress]
  )

  const handleDownloadAttachment = useCallback(async (attachment) => {
    try {
      if (!attachment) {
        throw new Error('Attachment is missing')
      }

      let attachmentData = attachment

      const attachmentKey = identityMaterialRef.current?.privateKey || ''

      // If attachment needs to be fetched from Synapse, fetch it first
      if (attachment._needsFetch && attachment.cid && attachment.pieceCid && attachmentKey) {
        setStatusMessage('Fetching attachment from storage...')
        try {
          attachmentData = await fetchAttachment(
            {
              cid: attachment.cid,
              pieceCid: attachment.pieceCid,
              providerInfo: attachment.providerInfo,
              encryptedMetadata: attachment.encryptedMetadata,
            },
            attachmentKey
          )
          // Update the attachment in the selected email to cache it
          if (selectedEmail?.decrypted?.attachments) {
            const updatedAttachments = selectedEmail.decrypted.attachments.map((att) =>
              att.cid === attachment.cid ? attachmentData : att
            )
            setSelectedEmail({
              ...selectedEmail,
              decrypted: {
                ...selectedEmail.decrypted,
                attachments: updatedAttachments,
              },
            })
          }
        } catch (fetchError) {
          console.error('Failed to fetch attachment from Synapse:', fetchError)
          throw new Error(`Failed to fetch attachment: ${fetchError.message}`)
        }
      } else if (attachment._needsFetch && !attachmentKey) {
        throw new Error('Identity key required to decrypt this attachment.')
      }

      if (!attachmentData.data) {
        throw new Error('Attachment data is missing')
      }

      // Decode base64 data
      const base64Data = attachmentData.data
      const binaryString = atob(base64Data)
      const bytes = new Uint8Array(binaryString.length)
      for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i)
      }

      // Create blob from bytes
      const blob = new Blob([bytes], { type: attachmentData.mimeType || 'application/octet-stream' })

      // Create download link
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = attachmentData.filename || 'attachment'
      document.body.appendChild(link)
      link.click()

      // Cleanup
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
      setStatusMessage('')
    } catch (error) {
      console.error('Failed to download attachment:', error)
      setErrorMessage(`Failed to download attachment: ${error.message}`)
      setStatusMessage('')
    }
  }, [selectedEmail])

  const handleSaveEvent = useCallback(
    async (eventInput) => {
      setSavingEvent(true)
      setCalendarError('')
      try {
        const ensProvider = await getEnsProvider()
        const browserProvider = (await ensureProvider()) ?? provider
        const signer = await browserProvider.getSigner()
        const ownerEns = ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)
        if (!ownerEns) {
          throw new Error('ENS name not resolved for calendar')
        }

        let calendarData = null
        if (calendarUploadResult?.cid && calendarUploadResult?.pieceCid) {
          calendarData = await loadCalendarFromCidFile(calendarUploadResult, { optional: true })
        }
        if (!calendarData) {
          calendarData = createEmptyCalendar(ownerEns)
        }

        const updatedCalendar = appendCalendarEvent(calendarData, eventInput)
        const uploadResult = await persistCalendar(updatedCalendar, {
          owner: ownerEns,
          uploadOptions: {
            metadata: {
              type: 'dmail-calendar',
              owner: ownerEns,
            },
          },
        })

        await setCalendarUploadResult(ownerEns, uploadResult, { signer, wait: true })
        setCalendarUploadResultState(uploadResult)
        setCalendarEvents(updatedCalendar.events)
        setShowEventModal(false)
      } catch (error) {
        console.error(error)
        setCalendarError(error.message ?? 'Failed to save event')
      } finally {
        setSavingEvent(false)
      }
    },
    [calendarUploadResult, ensName, ensureProvider, getEnsProvider, provider, walletAddress]
  )

  const handleSend = useCallback(
    async (event) => {
      event?.preventDefault()
      setSending(true)
      setErrorMessage('')
      setStatusMessage('Encrypting email...')
      try {
        await ensureProvider()
        const ensProvider = await getEnsProvider()
        const senderEns =
          ensName ?? (walletAddress ? await ensProvider.lookupAddress(walletAddress) : null)

        if (!senderEns) {
          throw new Error('ENS name not resolved for connected wallet. Set one before sending.')
        }

        const recipientEns = composeState.to
        if (!recipientEns) {
          throw new Error('Recipient ENS name is required')
        }

        const recipientPublicKey =
          composeState.recipientPublicKey ||
          (await resolvePublicKey(recipientEns, { provider: ensProvider, ensName: recipientEns })) ||
          import.meta.env.VITE_RECIPIENT_PUBLIC_KEY

        if (!recipientPublicKey) {
          throw new Error(
            `Recipient public key missing. Ask ${recipientEns} to open dMail v2 once or provide a manual key.`
          )
        }

        const activeIdentity = identityMaterialRef.current ?? (await ensureIdentityMaterial(senderEns))
        if (!activeIdentity) {
          throw new Error('Unable to prepare identity keys. Reconnect wallet and try again.')
        }
        if (!activeIdentity.signingKey || !activeIdentity.signingPublicKey) {
          throw new Error('Identity signing material missing. Reconnect wallet to derive identity again.')
        }

        const timestamp = Date.now()
        const subjectPreview = composeState.subject?.slice(0, 120) ?? ''
        const attachmentSummaries = composeState.attachments.map((attachment, index) => ({
          filename: attachment.filename || `attachment-${index + 1}`,
          mimeType: attachment.mimeType || 'application/octet-stream',
        }))
        
        // Upload attachments to Synapse if any
        if (composeState.attachments.length > 0) {
          setStatusMessage(`Uploading ${composeState.attachments.length} attachment(s) to Filecoin storage...`)
        }
        
        const encryptedEmail = await encryptEmail(
          {
            from: senderEns,
            to: recipientEns,
            subject: composeState.subject,
            message: composeState.message,
            attachments: composeState.attachments,
            timestamp,
          },
          recipientPublicKey,
          {
            uploadAttachmentsToSynapse: true,
            senderIdentity: activeIdentity,
          }
        )

        let recipientUpload = null
        let senderUpload = null
        if (encryptedEmail?.version >= 2 && encryptedEmail?.recipientEnvelope) {
          setStatusMessage('Uploading encrypted recipient copy to Filecoin storage...')
          recipientUpload = await synapseUpload(encryptedEmail.recipientEnvelope, {
            filename: `email-${senderEns}-${timestamp}.json`,
            metadata: {
              type: 'dmail-email-recipient',
              from: senderEns,
              to: recipientEns,
              messageId: encryptedEmail.messageId,
            },
          })

          if (encryptedEmail.senderEnvelope) {
            setStatusMessage('Uploading encrypted sender copy to Filecoin storage...')
            senderUpload = await synapseUpload(encryptedEmail.senderEnvelope, {
              filename: `email-${senderEns}-sent-${timestamp}.json`,
              metadata: {
                type: 'dmail-email-sender',
                from: senderEns,
                to: recipientEns,
                messageId: encryptedEmail.messageId,
              },
            })
          }
        } else {
          setStatusMessage('Uploading encrypted email to Filecoin storage...')
          recipientUpload = await synapseUpload(encryptedEmail, {
            filename: `email-${senderEns}-${timestamp}.json`,
            metadata: {
              type: 'dmail-email',
              from: senderEns,
              to: recipientEns,
            },
          })
        }

        setStatusMessage('Resolving mailbox pointers...')
        const [recipientMailboxRootRaw, senderMailboxRootRaw] = await Promise.all([
          resolveMailboxRoot(recipientEns, {
            provider: ensProvider,
          }),
          resolveMailboxRoot(senderEns, {
            provider: ensProvider,
          }),
        ])
        const recipientMailboxRoot = normalizeMailboxRoot(recipientMailboxRootRaw, {
          owner: recipientEns,
        })
        const senderMailboxRoot = normalizeMailboxRoot(senderMailboxRootRaw, {
          owner: senderEns,
        })

        const toRecipients = [recipientEns]
        const ccRecipients = []
        const signatureMetadata = {
          messageId: encryptedEmail.messageId,
          bodyCid: recipientUpload?.cid ?? null,
          keyEnvelopesCid: recipientUpload?.cid ?? null,
          senderCopyCid: senderUpload?.cid ?? null,
          from: senderEns,
          to: toRecipients,
          cc: ccRecipients,
          timestamp,
          ephemeralPublicKey: encryptedEmail.recipientEnvelope?.ephemeralPublicKey ?? null,
        }
        if (!signatureMetadata.bodyCid || !signatureMetadata.keyEnvelopesCid) {
          throw new Error('Failed to compute signature metadata for this message. Try again.')
        }
        const metadataHash = computeEnvelopeMetadataHash(signatureMetadata)
        const signature = signEnvelope(activeIdentity.signingKey, metadataHash)

        const entryMetadata = {
          from: senderEns,
          to: recipientEns,
          toRecipients,
          cc: ccRecipients,
          timestamp,
          subjectPreview,
          messageId: encryptedEmail.messageId,
          attachments: attachmentSummaries,
          ephemeralPublicKey: encryptedEmail.recipientEnvelope?.ephemeralPublicKey ?? null,
          signature,
          signerPublicKey: activeIdentity.signingPublicKey,
          bodyCid: signatureMetadata.bodyCid,
          keyEnvelopesCid: signatureMetadata.keyEnvelopesCid,
          senderCopyCid: signatureMetadata.senderCopyCid,
        }

        setStatusMessage('Appending inbox index entry...')
        const recipientMailboxUpdate = await appendInboxEntry({
          ownerEns: recipientEns,
          mailboxRoot: recipientMailboxRoot,
          uploads: { recipient: recipientUpload, sender: senderUpload },
          metadata: entryMetadata,
          persistOptions: {
            metadataType: 'dmail-mailbox-inbox',
          },
          resolveOptions: { provider: ensProvider },
          resolverOptions: { provider: ensProvider },
        })

        setStatusMessage('Appending sent index entry...')
        const senderMailboxUpdate = await appendSentEntry({
          ownerEns: senderEns,
          mailboxRoot: senderMailboxRoot,
          uploads: { recipient: recipientUpload, sender: senderUpload },
          metadata: { ...entryMetadata, folder: 'sent' },
          persistOptions: {
            metadataType: 'dmail-mailbox-sent',
          },
          resolveOptions: { provider: ensProvider },
          resolverOptions: { provider: ensProvider },
        })
        setMailboxRoot(senderMailboxUpdate.mailboxRoot)

        setStatusMessage('Email sent successfully!')
        updateCompose({ to: '', subject: '', message: '', recipientPublicKey: '', attachments: [] })
        setPubKeyFetchError(null)
        setShowManualPubKey(false)
        setFetchingPubKey(false)
        setShowCompose(false)
        await refreshInbox()
      } catch (error) {
        console.error(error)
        setErrorMessage(error.message ?? 'Failed to send email')
      } finally {
        setSending(false)
      }
    },
    [
      composeState.attachments,
      composeState.message,
      composeState.recipientPublicKey,
      composeState.subject,
      composeState.to,
      ensureProvider,
      ensName,
      provider,
      refreshInbox,
      walletAddress,
      getEnsProvider,
      identityPublicKey,
      ensureIdentityMaterial,
    ]
  )

  const filteredEmails = useMemo(() => {
    const source = activeView === 'sent' ? sentEntries : mailboxEntries
    const sorted = [...source].sort((a, b) => (b.timestamp ?? 0) - (a.timestamp ?? 0))
    if (!searchQuery) return sorted
    const query = searchQuery.toLowerCase()
    return sorted.filter(
      (entry) =>
        entry.from?.toLowerCase().includes(query) ||
        (Array.isArray(entry.toRecipients)
          ? entry.toRecipients.join(', ').toLowerCase().includes(query)
          : entry.to?.toLowerCase().includes(query)) ||
        entry.subjectPreview?.toLowerCase().includes(query)
    )
  }, [mailboxEntries, sentEntries, searchQuery, activeView])

  const formatTime = (timestamp) => {
    const date = new Date(timestamp)
    const now = new Date()
    const diff = now - date
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    
    if (days === 0) {
      return date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' })
    } else if (days < 7) {
      return date.toLocaleDateString('en-US', { weekday: 'short' })
    } else {
      return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
    }
  }

  const getSignatureStatusClass = (status) => {
    if (status === true) return 'signature-valid'
    if (status === false) return 'signature-invalid'
    return 'signature-unsigned'
  }

  const getSignatureStatusIcon = (status) => {
    if (status === true) return '✓'
    if (status === false) return '⚠️'
    return '∙'
  }

  const getSignatureStatusTitle = (status) => {
    if (status === true) return 'Signature verified'
    if (status === false) return 'Signature invalid'
    return 'Unsigned message'
  }

  return (
    <div className="gmail-layout">
      {/* Header */}
      <header className="gmail-header">
        <div className="header-left">
          <button className="menu-btn" aria-label="Menu">☰</button>
          <h1 className="logo">
            <span className="logo-icon">📧</span>
            dMail
          </h1>
        </div>
        
        <div className="header-center">
          <div className="search-bar">
            <span className="search-icon">🔍</span>
            <input
              type="text"
              placeholder="Search mail"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>
        </div>

        <div className="header-right">
          {walletAddress ? (
            <div className="wallet-status">
              <span className="wallet-indicator connected">●</span>
              <span className="user-info" title={walletAddress}>
                {ensName || `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`}
              </span>
            </div>
          ) : (
            <>
              <button className="icon-btn" onClick={connectWallet} title="Connect Wallet">
                🔌
              </button>
              <span className="user-info">Not connected</span>
            </>
          )}
        </div>
      </header>

      {/* Status Messages - filter out wallet connection status since it's in navbar */}
      {statusMessage && statusMessage !== 'Wallet connected' && (
        <div className="toast toast-success">{statusMessage}</div>
      )}
      {errorMessage && <div className="toast toast-error">{errorMessage}</div>}

      <div className="gmail-container">
        {/* Sidebar */}
        <aside className={`gmail-sidebar ${calendarFullPage ? 'hidden' : ''}`}>
          <button
            className="compose-btn"
            onClick={() => setShowCompose(true)}
            disabled={!walletAddress}
          >
            <span className="compose-icon">✏️</span>
            Compose
          </button>

          <nav className="sidebar-nav">
            <button
              className={activeView === 'inbox' ? 'nav-item active' : 'nav-item'}
              onClick={() => setActiveView('inbox')}
            >
              <span className="nav-icon">📥</span>
              <span className="nav-label">Inbox</span>
              <span className="nav-count">{mailboxEntries.length}</span>
            </button>
            <button className="nav-item" onClick={() => alert('Not implemented')}>
              <span className="nav-icon">⭐</span>
              <span className="nav-label">Starred</span>
            </button>
            <button
              className={activeView === 'sent' ? 'nav-item active' : 'nav-item'}
              onClick={() => setActiveView('sent')}
            >
              <span className="nav-icon">📤</span>
              <span className="nav-label">Sent</span>
              <span className="nav-count">{sentEntries.length}</span>
            </button>
            <button className="nav-item" onClick={() => alert('Not implemented')}>
              <span className="nav-icon">📝</span>
              <span className="nav-label">Drafts</span>
            </button>
          </nav>

          <div className="sidebar-footer">
            <button className="text-btn" onClick={refreshInbox} disabled={!walletAddress || loadingInbox}>
              {loadingInbox ? '⏳ Loading...' : '🔄 Refresh'}
            </button>
            <div className="private-key-section">
              <label className="key-label">
                🔐 Identity (derived)
                <span className="key-hint" title="Derived from your wallet signature and registered via the resolver.">
                  ℹ️
                </span>
              </label>
              <input
                type="text"
                className="key-input"
                placeholder="Connect wallet to derive identity"
                value={identityPublicKey ?? ''}
                readOnly
              />
              {(identityDeriving || identityStatusMessage) && (
                <div className="key-help identity-status">
                  <small>
                    {identityDeriving
                      ? 'Generating dMail identity… approve MetaMask if prompted.'
                      : identityStatusMessage}
                  </small>
                </div>
              )}
              <button
                type="button"
                className="text-btn"
                onClick={handleRegenerateIdentity}
                disabled={!walletAddress || identityDeriving}
              >
                {identityDeriving ? 'Deriving identity…' : '♻️ Regenerate identity'}
              </button>
            </div>
          </div>
        </aside>

        {/* Email List */}
        <main className={`gmail-main ${calendarFullPage ? 'hidden' : ''}`}>
          <div className="toolbar">
            <div className="toolbar-left">
              <input type="checkbox" className="select-all" />
              <button className="toolbar-btn" title="Refresh" onClick={refreshInbox}>
                ↻
              </button>
            </div>
          </div>

          <div className="email-list">
            {loadingInbox ? (
              <div className="empty-state">Loading inbox...</div>
            ) : filteredEmails.length === 0 ? (
              <div className="empty-state">
                {searchQuery
                  ? 'No emails match your search'
                  : activeView === 'sent'
                  ? 'Your sent folder is empty'
                  : 'Your inbox is empty'}
              </div>
            ) : (
              filteredEmails.map((entry) => {
                const entryKey = entry.messageId ?? entry.cidSender ?? entry.cid
                const isActive = selectedEmail?.entry?.messageId
                  ? selectedEmail.entry.messageId === entry.messageId
                  : selectedEmail?.entry?.cid === entry.cid
                return (
                  <div
                    key={entryKey}
                    className={`email-item ${isActive ? 'active' : ''}`}
                    onClick={() => openEmail(entry)}
                  >
                    <input type="checkbox" className="email-checkbox" onClick={(e) => e.stopPropagation()} />
                    <span className="email-star">☆</span>
                    <span className="email-sender">{entry.from || 'Unknown'}</span>
                    <span className="email-subject">
                      {entry.subjectPreview || '(No subject)'}
                      <span
                        className={`signature-badge ${getSignatureStatusClass(entry._signatureValid)}`}
                        title={getSignatureStatusTitle(entry._signatureValid)}
                      >
                        {getSignatureStatusIcon(entry._signatureValid)}
                      </span>
                    </span>
                    <span className="email-time">{formatTime(entry.timestamp)}</span>
                  </div>
                )
              })
            )}
          </div>
        </main>

        {/* Email Viewer */}
        <section className={`gmail-viewer ${selectedEmail && !calendarFullPage ? 'open' : ''}`}>
          {selectedEmail ? (
            <div className="email-detail">
              <div className="email-header">
                <h2 className="email-title">{selectedEmail.decrypted.subject}</h2>
                <div className="email-actions">
                  <button className="icon-btn" title="Reply">↩️</button>
                  <button className="icon-btn" title="Archive">🗄️</button>
                  <button className="icon-btn" title="Delete">🗑️</button>
                  <button className="icon-btn" onClick={() => setSelectedEmail(null)} title="Close">
                    ✕
                  </button>
                </div>
              </div>

              <div className="email-meta">
                <div className="sender-info">
                  <div className="sender-avatar">{selectedEmail.decrypted.from?.[0]?.toUpperCase() || '?'}</div>
                  <div className="sender-details">
                    <div className="sender-name">{selectedEmail.decrypted.from}</div>
                    <div className="sender-email">to {selectedEmail.decrypted.to}</div>
                    {Array.isArray(selectedEmail.entry?.cc) && selectedEmail.entry.cc.length > 0 && (
                      <div className="sender-email cc-line">cc {selectedEmail.entry.cc.join(', ')}</div>
                    )}
                  </div>
                </div>
                <div className="email-timestamp">
                  {new Date(selectedEmail.decrypted.timestamp).toLocaleString()}
                </div>
              </div>
              <div className="email-flags">
                {selectedEmail.entry?.folder === 'sent' && <span className="pill pill-sent">Sent</span>}
                {selectedEmail.entry?.signature && (
                  <span
                    className={`pill ${
                      selectedEmail.signatureValid === false
                        ? 'pill-error'
                        : selectedEmail.signatureValid
                        ? 'pill-success'
                        : 'pill-neutral'
                    }`}
                  >
                    {selectedEmail.signatureValid === false
                      ? '⚠️ Signature invalid'
                      : selectedEmail.signatureValid
                      ? '✓ Signature verified'
                      : 'Unsigned'}
                  </span>
                )}
              </div>

              <div className="email-body">
                <pre>{selectedEmail.decrypted.message}</pre>
              </div>

              {Array.isArray(selectedEmail.decrypted.attachments) &&
                selectedEmail.decrypted.attachments.length > 0 && (
                  <div className="email-attachments">
                    <div className="attachments-header">📎 {selectedEmail.decrypted.attachments.length} attachment(s)</div>
                    <div className="attachments-list">
                      {selectedEmail.decrypted.attachments.map((attachment, idx) => (
                        <div
                          key={idx}
                          className="attachment-item"
                          onClick={() => handleDownloadAttachment(attachment)}
                          title="Click to download"
                        >
                          <span className="attachment-icon">📄</span>
                          <span className="attachment-name">{attachment.filename}</span>
                          <span className="attachment-size">({attachment.mimeType})</span>
                          <span className="attachment-download">⬇</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
            </div>
          ) : (
            <div className="empty-viewer">
              <div className="empty-icon">📭</div>
              <p>Select an email to read</p>
            </div>
          )}
        </section>

        <CalendarSidebar
          events={calendarEvents}
          loading={calendarLoading}
          error={calendarError}
          onRefresh={refreshCalendar}
          onAddEvent={() => setShowEventModal(true)}
          onShareEvent={handleShareEvent}
          fullPage={calendarFullPage}
          onToggleFullPage={() => setCalendarFullPage(!calendarFullPage)}
        />
      </div>

      {/* Compose Modal */}
      {showCompose && (
        <div
          className="compose-modal-overlay"
          onClick={() => {
            setShowCompose(false)
            // Reset state when modal closes
            setPubKeyFetchError(null)
            setShowManualPubKey(false)
            setFetchingPubKey(false)
          }}
        >
          <div className="compose-modal" onClick={(e) => e.stopPropagation()}>
            <div className="compose-header">
              <h3>New Message</h3>
              <button
                className="close-btn"
                onClick={() => {
                  setShowCompose(false)
                  // Reset state when modal closes
                  setPubKeyFetchError(null)
                  setShowManualPubKey(false)
                  setFetchingPubKey(false)
                }}
              >
                ✕
              </button>
            </div>

            <form className="compose-form" onSubmit={handleSend}>
              <div className="compose-field">
                <input
                  type="text"
                  placeholder="To (ENS name, e.g. alice.eth)"
                  value={composeState.to}
                  onChange={(e) => {
                    const ensName = e.target.value.trim()
                    updateCompose({ to: ensName })
                    // Auto-fetch public key when ENS name is entered
                    if (ensName && ensName.endsWith('.eth')) {
                      fetchRecipientPublicKey(ensName)
                    } else {
                      setPubKeyFetchError(null)
                      setShowManualPubKey(false)
                      updateCompose({ recipientPublicKey: '' })
                    }
                  }}
                  onBlur={(e) => {
                    // Also try fetching on blur if not already fetched
                    const ensName = e.target.value.trim()
                    if (ensName && ensName.endsWith('.eth') && !composeState.recipientPublicKey) {
                      fetchRecipientPublicKey(ensName)
                    }
                  }}
                  required
                />
                {fetchingPubKey && (
                  <div className="field-status">🔍 Looking up public key from ENS...</div>
                )}
                {composeState.recipientPublicKey && !fetchingPubKey && !pubKeyFetchError && (
                  <div className="field-status success">✓ Public key found and loaded</div>
                )}
                {pubKeyFetchError && (
                  <div className="field-status error">{pubKeyFetchError}</div>
                )}
              </div>

              {(showManualPubKey || composeState.recipientPublicKey) && (
                <div className="compose-field">
                  <input
                    type="text"
                    placeholder="Recipient Public Key (optional override)"
                    value={composeState.recipientPublicKey}
                    onChange={(e) => {
                      updateCompose({ recipientPublicKey: e.target.value })
                      // If user manually enters a key, clear error
                      if (e.target.value) {
                        setPubKeyFetchError(null)
                      }
                    }}
                  />
                  <div className="field-help">
                    <small>
                      ℹ️ Only needed if ENS lookup failed. Usually auto-filled from {composeState.to || 'recipient'} ENS record.
                    </small>
                  </div>
                </div>
              )}

              <div className="compose-field">
                <input
                  type="text"
                  placeholder="Subject"
                  value={composeState.subject}
                  onChange={(e) => updateCompose({ subject: e.target.value })}
                  required
                />
              </div>

              <div className="compose-body">
                <textarea
                  placeholder="Message"
                  value={composeState.message}
                  onChange={(e) => updateCompose({ message: e.target.value })}
                  required
                />
              </div>

              {composeState.attachments.length > 0 && (
                <div className="compose-attachments">
                  {composeState.attachments.map((attachment, idx) => (
                    <div key={idx} className="compose-attachment">
                      📎 {attachment.filename}
                    </div>
                  ))}
                </div>
              )}

              <div className="compose-footer">
                <button type="submit" className="send-btn" disabled={sending}>
                  {sending ? '⏳ Sending...' : '📤 Send'}
        </button>
                <label className="attach-btn">
                  📎 Attach
                  <input type="file" multiple onChange={handleAttachments} style={{ display: 'none' }} />
                </label>
              </div>
            </form>
          </div>
        </div>
      )}

      {showEventModal && (
        <EventModal onClose={() => setShowEventModal(false)} onSave={handleSaveEvent} saving={savingEvent} />
      )}
      </div>
  )
}

async function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader()
    reader.onload = () => {
      const result = reader.result
      if (typeof result === 'string') {
        const base64 = result.split(',').pop()
        resolve(base64 ?? '')
      } else {
        resolve('')
      }
    }
    reader.onerror = (error) => reject(error)
    reader.readAsDataURL(file)
  })
}

export default App
